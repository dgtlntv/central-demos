import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

import pytz
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path to docker-compose file
COMPOSE_FILE = "/docker-compose/docker-compose.yml"

# Scheduler instance
scheduler: Optional[AsyncIOScheduler] = None

# CET timezone
CET = pytz.timezone("CET")


class RebuildResponse(BaseModel):
    status: str
    message: str
    timestamp: str


class RebuildRequest(BaseModel):
    service: str


class SchedulerResponse(BaseModel):
    status: str
    message: str
    next_run: Optional[str] = None
    timestamp: str


# Available services that can be rebuilt
REBUILDABLE_SERVICES = ["maas-frontend", "app2-frontend"]


async def run_command(command: List[str]) -> tuple[int, str, str]:
    """Run a shell command asynchronously"""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/docker-compose",
        )
        stdout, stderr = await process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return 1, "", str(e)


async def background_rebuild(service_name: str):
    """Background task for rebuilding a service"""
    logger.info(f"Starting rebuild of {service_name}")

    # Build the service
    build_cmd = [
        "docker-compose",
        "-f",
        COMPOSE_FILE,
        "build",
        "--no-cache",
        service_name,
    ]
    returncode, stdout, stderr = await run_command(build_cmd)

    if returncode != 0:
        logger.error(f"Build failed for {service_name}: {stderr}")
        return

    logger.info(f"Build completed for {service_name}")

    # Restart the service
    restart_cmd = [
        "docker-compose",
        "-f",
        COMPOSE_FILE,
        "up",
        "-d",
        service_name,
    ]
    returncode, stdout, stderr = await run_command(restart_cmd)

    if returncode != 0:
        logger.error(f"Restart failed for {service_name}: {stderr}")
        return

    logger.info(f"Successfully rebuilt and restarted {service_name}")

    # Clean up unused images after successful rebuild
    cleanup_cmd = ["docker", "image", "prune", "-f"]
    returncode, stdout, stderr = await run_command(cleanup_cmd)

    if returncode != 0:
        logger.warning(f"Image cleanup failed for {service_name}: {stderr}")
    else:
        logger.info(
            f"Cleaned up unused images after rebuilding {service_name}"
        )


async def scheduled_rebuild_all():
    """Scheduled task to rebuild all services daily"""
    logger.info("Starting scheduled daily rebuild of all services")

    for service in REBUILDABLE_SERVICES:
        await background_rebuild(service)

    logger.info("Scheduled daily rebuild completed")


def setup_scheduler():
    """Setup the scheduler with daily rebuild at midnight CET"""
    global scheduler

    if scheduler is None:
        scheduler = AsyncIOScheduler(timezone=CET)

        # Schedule daily rebuild at midnight CET
        scheduler.add_job(
            scheduled_rebuild_all,
            CronTrigger(hour=0, minute=0, timezone=CET),
            id="daily_rebuild",
            name="Daily rebuild of all services",
            replace_existing=True,
        )

        scheduler.start()
        logger.info(
            "Scheduler started - daily rebuilds scheduled for midnight CET"
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    # Startup
    setup_scheduler()
    yield
    # Shutdown
    global scheduler
    if scheduler:
        scheduler.shutdown()
        logger.info("Scheduler shutdown")


app = FastAPI(
    title="Docker Management API", version="1.0.0", lifespan=lifespan
)


@app.get("/")
async def root():
    return {
        "message": "Docker Management API",
        "available_endpoints": [
            "/rebuild/{service}",
            "/rebuild-all",
            "/status",
            "/services",
            "/scheduler/status",
            "/scheduler/start",
            "/scheduler/stop",
            "/cleanup",
        ],
    }


@app.get("/services")
async def get_services():
    """Get list of rebuildable services"""
    return {"services": REBUILDABLE_SERVICES}


@app.post("/rebuild/{service}")
async def rebuild_service(service: str, background_tasks: BackgroundTasks):
    """Rebuild a specific service"""
    if service not in REBUILDABLE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Service '{service}' is not rebuildable. Available services: {REBUILDABLE_SERVICES}",
        )

    background_tasks.add_task(background_rebuild, service)

    return RebuildResponse(
        status="initiated",
        message=f"Rebuild of {service} has been initiated",
        timestamp=datetime.now().isoformat(),
    )


@app.post("/rebuild-all")
async def rebuild_all_services(background_tasks: BackgroundTasks):
    """Rebuild all rebuildable services"""
    for service in REBUILDABLE_SERVICES:
        background_tasks.add_task(background_rebuild, service)

    return RebuildResponse(
        status="initiated",
        message=f"Rebuild of all services has been initiated: {', '.join(REBUILDABLE_SERVICES)}",
        timestamp=datetime.now().isoformat(),
    )


@app.get("/scheduler/status")
async def get_scheduler_status():
    """Get scheduler status and next scheduled run"""
    global scheduler

    if not scheduler or not scheduler.running:
        return SchedulerResponse(
            status="stopped",
            message="Scheduler is not running",
            timestamp=datetime.now().isoformat(),
        )

    # Get next scheduled job
    jobs = scheduler.get_jobs()
    daily_rebuild_job = next(
        (job for job in jobs if job.id == "daily_rebuild"), None
    )

    next_run = None
    if daily_rebuild_job and daily_rebuild_job.next_run_time:
        next_run = daily_rebuild_job.next_run_time.isoformat()

    return SchedulerResponse(
        status="running",
        message="Scheduler is running",
        next_run=next_run,
        timestamp=datetime.now().isoformat(),
    )


@app.post("/scheduler/start")
async def start_scheduler():
    """Start the scheduler"""
    global scheduler

    if scheduler and scheduler.running:
        return SchedulerResponse(
            status="already_running",
            message="Scheduler is already running",
            timestamp=datetime.now().isoformat(),
        )

    setup_scheduler()

    return SchedulerResponse(
        status="started",
        message="Scheduler started successfully",
        timestamp=datetime.now().isoformat(),
    )


@app.post("/scheduler/stop")
async def stop_scheduler():
    """Stop the scheduler"""
    global scheduler

    if not scheduler or not scheduler.running:
        return SchedulerResponse(
            status="already_stopped",
            message="Scheduler is already stopped",
            timestamp=datetime.now().isoformat(),
        )

    scheduler.shutdown(wait=False)
    scheduler = None

    return SchedulerResponse(
        status="stopped",
        message="Scheduler stopped successfully",
        timestamp=datetime.now().isoformat(),
    )


@app.get("/status")
async def get_status():
    """Get status of all services"""
    cmd = ["docker-compose", "-f", COMPOSE_FILE, "ps", "--format", "json"]
    returncode, stdout, stderr = await run_command(cmd)

    if returncode != 0:
        raise HTTPException(
            status_code=500, detail=f"Failed to get status: {stderr}"
        )

    return {
        "status": "success",
        "services": stdout,
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/cleanup")
async def cleanup_images():
    """Clean up unused Docker images"""
    cmd = ["docker", "image", "prune", "-f"]
    returncode, stdout, stderr = await run_command(cmd)

    if returncode != 0:
        raise HTTPException(
            status_code=500, detail=f"Cleanup failed: {stderr}"
        )

    return RebuildResponse(
        status="success",
        message="Docker image cleanup completed",
        timestamp=datetime.now().isoformat(),
    )
