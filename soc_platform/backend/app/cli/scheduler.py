import argparse
import time
from datetime import datetime

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.hydration_queue import hydration_queue_service
from app.services.scheduler import scheduler_service

settings = get_settings()


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def run_scheduler_tick(
    process_hydration: bool,
    hydration_limit: int,
) -> None:
    db = SessionLocal()

    try:
        summary_result = scheduler_service.run_due_summary_syncs(db)

        log(
            f"SUMMARY_SYNC_TICK | due_configs={summary_result['due_configs']} | "
            f"results={summary_result['results']}"
        )

        if process_hydration:
            hydration_result = hydration_queue_service.process_due_jobs(
                db=db,
                limit=hydration_limit,
            )

            log(
                f"HYDRATION_TICK | processed={hydration_result['processed']} | "
                f"hydrated={hydration_result['hydrated']} | "
                f"partial={hydration_result['partial']} | "
                f"failed={hydration_result['failed']}"
            )

    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified SOC Platform realtime scheduler"
    )

    parser.add_argument(
        "--tick-seconds",
        type=int,
        default=settings.scheduler_tick_seconds,
        help="How often the scheduler checks for due polling configs",
    )

    parser.add_argument(
        "--hydration-limit",
        type=int,
        default=settings.scheduler_hydration_batch_size,
        help="Max hydration jobs to process per tick",
    )

    parser.add_argument(
        "--disable-hydration",
        action="store_true",
        help="Disable hydration queue processing",
    )

    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run one scheduler tick and exit",
    )

    args = parser.parse_args()

    process_hydration = settings.scheduler_hydration_enabled and not args.disable_hydration

    log(
        f"SCHEDULER_STARTED | tick_seconds={args.tick_seconds} | "
        f"hydration_enabled={process_hydration} | "
        f"hydration_limit={args.hydration_limit} | "
        f"run_once={args.run_once}"
    )

    if args.run_once:
        run_scheduler_tick(
            process_hydration=process_hydration,
            hydration_limit=args.hydration_limit,
        )
        log("SCHEDULER_FINISHED_RUN_ONCE")
        return

    while True:
        tick_start = datetime.now()

        run_scheduler_tick(
            process_hydration=process_hydration,
            hydration_limit=args.hydration_limit,
        )

        elapsed = (datetime.now() - tick_start).total_seconds()
        sleep_for = max(args.tick_seconds - elapsed, 0)

        log(
            f"SCHEDULER_SLEEP | elapsed={elapsed:.2f}s | sleep_for={sleep_for:.2f}s"
        )

        time.sleep(sleep_for)


if __name__ == "__main__":
    main()