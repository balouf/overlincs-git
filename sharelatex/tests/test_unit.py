import datetime
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Mapping, Sequence
from typing import cast as typing_cast
from unittest.mock import MagicMock, patch

from sharelatex.cli import RemoteItem, _sync_deleted_items, _sync_remote_files


@contextmanager
def into_tmpdir() -> Generator:
    """Run some code in the context of a tmp dir."""

    old_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            os.chdir(tmp_dir)
            yield tmp_dir
        except Exception as e:
            raise e
        finally:
            os.chdir(old_cwd)


def tmpdir(f: Any) -> Any:
    """
    Temporary directory.
    """

    def _wrapped(*args: Any, **kwargs: Any) -> None:
        with into_tmpdir() as tmpdir:  # type: ignore
            # create a dummy env there
            f(*args, Path(tmpdir), **kwargs)

    return _wrapped


class TestPull(unittest.TestCase):
    @patch.object(Path, "rmdir")
    @patch.object(Path, "unlink")
    def test_sync_delete_file_nomore_present_on_server(
        self, mock_unlink: Any, mock_rmdir: Any
    ) -> None:
        # simple test one empty folder in the remote server
        remote_items = typing_cast(
            Sequence[RemoteItem],
            [
                # the rootFolder
                {"folder_id": "0", "name": ".", "folder_path": ".", "type": "folder"}
            ],
        )
        # But one file locally (abs path)
        working_path = Path.cwd()
        f = Path("image.png").resolve()
        files = [f]

        _sync_deleted_items(working_path, remote_items, files)

        mock_rmdir.assert_not_called()
        mock_unlink.assert_called_once()
        mock_unlink.assert_called_with(f)

    @tmpdir  # type: ignore
    def test_sync_remote_files_download_new_files(self, _: Any) -> None:
        remote_items = typing_cast(
            Sequence[RemoteItem],
            [
                {
                    "folder_id": "rootFolderId",
                    "name": ".",
                    "folder_path": ".",
                    "type": "folder",
                },
                {
                    "_id": "myimageId",
                    "folder_id": "0",
                    "name": "myimage.png",
                    "folder_path": ".",
                    "type": "file",
                },
            ],
        )
        client = MagicMock()
        client.get_file = MagicMock()
        project_id = 0
        working_path = Path.cwd()
        # force to read local OS datetime (not git log datetime)
        datetimes_dict: Mapping[str, datetime.datetime] = {}
        _sync_remote_files(
            client, str(project_id), working_path, remote_items, datetimes_dict
        )

        client.get_file.assert_called_once()
        dest_path = working_path / "myimage.png"
        client.get_file.assert_called_with(
            str(project_id), "myimageId", dest_path=str(dest_path)
        )
