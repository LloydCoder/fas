from fas.collectors.filesystem import safe_read_bytes
def test_safe_reader_reads_regular_file(tmp_path):
    target=tmp_path/"safe.txt"; target.write_bytes(b"safe")
    assert safe_read_bytes(target,tmp_path,1024)==b"safe"
def test_safe_reader_rejects_symlink(tmp_path):
    target=tmp_path/"target.txt"; target.write_bytes(b"secret")
    link=tmp_path/"link.txt"; link.symlink_to(target)
    try:
        safe_read_bytes(link,tmp_path,1024)
    except (OSError,ValueError):
        return
    raise AssertionError("symlink must not be accepted")
