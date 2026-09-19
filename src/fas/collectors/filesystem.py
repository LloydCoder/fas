"""Filesystem safety checks for hostile repositories."""
from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass
@dataclass(frozen=True,slots=True)
class PathPolicy:
    root:Path
    max_files:int=100_000
    max_file_bytes:int=5*1024*1024
    def resolve(self,relative:str)->Path:
        candidate=(self.root/relative).resolve()
        root=self.root.resolve()
        try: candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("path escapes collection root") from exc
        return candidate
    def validate_relative(self,relative:str)->None:
        p=Path(relative)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError("absolute or parent traversal is forbidden")
def safe_walk(root:Path,policy:PathPolicy):
    count=0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if not (Path(current)/d).is_symlink())
        for name in sorted(files):
            path=Path(current)/name
            if path.is_symlink() or not path.is_file():
                continue
            size=path.stat().st_size
            count+=1
            if count>policy.max_files:
                raise ResourceLimitError("max_files exceeded")
            if size>policy.max_file_bytes:
                continue
            yield path
class ResourceLimitError(RuntimeError): pass

def safe_read_bytes(path:Path,root:Path,max_bytes:int)->bytes:
    """Read a regular file without following a final symlink when the platform exposes O_NOFOLLOW."""
    raw=Path(path)
    root=Path(root).resolve()
    if raw.is_symlink() or any(part.is_symlink() for part in [raw.parent, *raw.parent.parents] if part.exists()):
        raise ValueError("symlink paths are forbidden")
    resolved=raw.resolve()
    try: resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes collection root") from exc
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(resolved,flags)
    try:
        stat=os.fstat(fd)
        if not __import__("stat").S_ISREG(stat.st_mode):
            raise ValueError("not a regular file")
        if stat.st_size>max_bytes:
            raise ResourceLimitError("file exceeds max_bytes")
        chunks=[]
        remaining=max_bytes
        while remaining:
            chunk=os.read(fd,min(1024*1024,remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining-=len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
