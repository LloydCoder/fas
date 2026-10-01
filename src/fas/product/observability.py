"""Dependency-free structured observability primitives."""
from __future__ import annotations
import json, logging, time
from contextlib import contextmanager
from collections.abc import Iterator
logger=logging.getLogger("fas")
def configure_logging(level:str="INFO")->None:
    logging.basicConfig(level=getattr(logging,level.upper(),logging.INFO),format="%(message)s")
def emit(event:str,**fields:object)->None:
    logger.info(json.dumps({"event":event,**fields},sort_keys=True,default=str,separators=(",",":")))
@contextmanager
def timed(event:str,**fields:object)->Iterator[None]:
    started=time.monotonic()
    try: yield
    finally: emit(event,duration_ms=round((time.monotonic()-started)*1000,2),**fields)
