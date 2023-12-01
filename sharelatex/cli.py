import datetime
import getpass
import logging
import os
import sys
import tempfile
import time
from functools import wraps
from pathlib import Path
from typing import (
    AbstractSet,
    Any,
    Callable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
    cast,
)
from zipfile import ZipFile

import click
import dateutil.parser
import keyring
from git import Repo
from git.config import cp

from sharelatex import (
    AUTH_DICT,
    ProjectData,
    SyncClient,
    UpdateDatum,
    get_authenticator_class,
    set_logger,
    walk_folders,
    walk_project_data,
)

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict  # type: ignore

URL_MALFORMED_ERROR_MESSAGE = "projet_url is not well formed or missing"
AUTHENTICATION_FAILED = "Unable to authenticate, exiting"

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

set_logger(logger)


class RemoteItem(TypedDict):
    """
    Remote items.
    """

    type: str
    folder_path: str
    name: str
    _id: str
    created: str


class SharelatexError(Exception):
    """
    ShareLaTeX error.
    """

    def info(self) -> str:
        """
        Info.
        """
        return ""


class RepoNotCleanError(SharelatexError):
    """
    The repo is not clean.
    """

    def info(self) -> str:
        """
        the constant is used to check the error in the test
        a better version would be to give the list of files explicitly here
        for now we print the output of `git status` just before raising
        this exception.
        """
        return (
            f"\n---\n{MESSAGE_REPO_ISNT_CLEAN}. "
            "There mustn't be any untracked/uncommitted files here."
        )


def set_log_level(verbose: int = 0) -> None:
    """set log level from integer value"""
    log_levels = (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG)
    logger.setLevel(log_levels[verbose])


SLATEX_SECTION = "slatex"
SYNC_BRANCH = "__remote__sharelatex__"


def _commit_message(action: str) -> str:
    commit_message_base = "python-sharelatex "
    return commit_message_base + action


COMMIT_MESSAGE_PUSH: str = _commit_message("push")
COMMIT_MESSAGE_CLONE: str = _commit_message("clone")
COMMIT_MESSAGE_PREPULL: str = _commit_message("pre pull")
COMMIT_MESSAGE_UPLOAD: str = _commit_message("upload")
COMMIT_MESSAGES: AbstractSet[str] = frozenset(
    [
        COMMIT_MESSAGE_PUSH,
        COMMIT_MESSAGE_CLONE,
        COMMIT_MESSAGE_PREPULL,
        COMMIT_MESSAGE_UPLOAD,
    ]
)

MESSAGE_REPO_ISNT_CLEAN = "The repo isn't clean"

PROMPT_BASE_URL = "Base url: "
PROMPT_PROJECT_ID = "Project id: "
PROMPT_AUTH_TYPE = "Authentication type (*gitlab*|community|legacy): "
DEFAULT_AUTH_TYPE = "gitlab"
PROMPT_USERNAME = "Username: "
PROMPT_PASSWORD = "Password: "
PROMPT_CONFIRM = "Do you want to save your password in your OS keyring system (y/n) ?"
MAX_NUMBER_ATTEMPTS = 3


class RateLimiter:
    """Ensure not overpass the max_rate events by seconds by sleep an amount
    of time if necessary"""

    def event_inc_passthrough(self) -> None:
        """
        event_inc_passthrough
        """
        self.n_events += 1

    def event_inc(self, wait_interval: float = 0.1) -> None:
        """
        event_inc
        """
        t1 = time.time()
        self.n_events += 1
        while self.n_events / (t1 - self.t0) > self.max_rate:
            time.sleep(wait_interval)
            t1 = time.time()

    def __init__(self, max_rate: float) -> None:
        self.max_rate = max_rate
        self.n_events = 0
        self.t0 = time.time()

        # if self.max_rate <= 0.0:
        #     # TODO: PS -> Is this correct? Assigning method to method?
        #     self.event_inc = self.event_inc_passthrough


class Config:
    """Handle gitconfig read/write operations in a transparent way."""

    def __init__(self, repo: Repo):
        self.repo = repo
        self.keyring = keyring.get_keyring()

    def get_password(self, service: str, username: str) -> Optional[str]:
        """
        get_password
        """
        return cast(Optional[str], self.keyring.get_password(service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        """
        set_password
        """
        self.keyring.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        """
        delete_password
        """
        self.keyring.delete_password(service, username)

    def set_value(
        self,
        section: str,
        key: str,
        value: Union[str, bool],
        config_level: str = "repository",
    ) -> None:
        """Set a config value in a specific section.

        Note:
            If the section doesn't exist it is created.

        Args:
            section (str): the section name
            key (str): the key to set
            value (str): the value to set
        """
        with self.repo.config_writer(config_level) as c:
            try:
                c.set_value(section, key, value)
            except cp.NoSectionError as e:
                # No section is found, we create a new one
                logger.debug(e)
                c.set_value(section, "init", "")
            except Exception as e:
                raise e
            finally:
                c.release()

    def get_value(
        self,
        section: str,
        key: str,
        default: Optional[str] = None,
        config_level: Optional[str] = None,
    ) -> Union[int, str, float]:
        """Get a config value in a specific section of the config.

                Note: this returns the associated value if found.
                      Otherwise, it returns the default value.

                Args:
                    section (str): the section name: str
                    key (str): the key to set
                    default (str): the default value to apply
                    config_level (str): the config level to look for
                    see:
        https://gitpython.readthedocs.io/en/stable/reference.html#git.repo.base.Repo.config_level

        """
        with self.repo.config_reader(config_level) as c:
            try:
                value = c.get_value(section, key)
            except cp.NoSectionError as e:
                logger.debug(e)
                value = default
            except cp.NoOptionError as e:
                logger.debug(e)
                value = default
            except Exception as e:
                raise e
            finally:
                return value  # type: ignore


def get_clean_repo(path: Optional[Path] = None) -> Repo:
    """Create the git.repo object from a directory.

    Note:

        This initializes the git repository and fails if the repo isn't clean.
        This is run prior to many operations to make sure there isn't any
        untracked/uncommitted files in the repo.

    Args:
        path (str): the path of the repository in the local file system.

    Returns:
        a git.Repo data-structure.

    Raises:
        Exception if the repo isn't clean
    """
    repo = Repo.init(path=path)
    # Fail if the repo is clean
    if repo.is_dirty(index=True, working_tree=True, untracked_files=True):
        logger.error(repo.git.status())
        raise RepoNotCleanError()
    return repo


def refresh_project_information(
    repo: Repo,
    base_url: Optional[str] = None,
    project_id: Optional[str] = None,
    https_cert_check: Optional[bool] = None,
) -> Tuple[str, str, bool]:
    """Get and/or set the project information in/from the git config.

    If the information is set in the config it is retrieved, otherwise it is set.

    Args:
        repo (git.Repo): The repo object to read the config from
        base_url (str): the base_url to consider
        project_id (str): the project_id to consider
        https_cert_check (bool): Check the cert.
    Returns:
        tuple (base_url, project_id) after the refresh occurs.
    """
    config = Config(repo)
    if base_url is None:
        u = config.get_value(SLATEX_SECTION, "baseUrl")
        if u is not None:
            base_url = cast(str, u)
        else:
            base_url = input(PROMPT_BASE_URL)
            config.set_value(SLATEX_SECTION, "baseUrl", base_url)
    else:
        config.set_value(SLATEX_SECTION, "baseUrl", base_url)
    if project_id is None:
        p = config.get_value(SLATEX_SECTION, "projectId")
        if p is not None:
            project_id = cast(str, p)
        else:
            project_id = input(PROMPT_PROJECT_ID)
        config.set_value(SLATEX_SECTION, "projectId", project_id)
    else:
        config.set_value(SLATEX_SECTION, "projectId", project_id)
    if https_cert_check is None:
        c = cast(bool, config.get_value(SLATEX_SECTION, "httpsCertCheck"))
        if c is not None:
            https_cert_check = c
        else:
            https_cert_check = True
            config.set_value(SLATEX_SECTION, "httpsCertCheck", https_cert_check)
    else:
        config.set_value(SLATEX_SECTION, "httpsCertCheck", https_cert_check)

    return (
        base_url,
        project_id,
        https_cert_check,
    )


def refresh_account_information(
    repo: Repo,
    auth_type: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    save_password: Optional[bool] = None,
    ignore_saved_user_info: Optional[bool] = False,
) -> Tuple[str, str, str]:
    """Get and/or set the account information in/from the git config.

    If the information is set in the config it is retrieved, otherwise it is set.
    Note that no further encryption of the password is offered here.

    Args:
        repo (git.Repo): The repo object to read the config from
        username (str): The username to consider
        password (str): The password to consider
        save_password (boolean): True for save user account information (in OS
                                 keyring system) if needed
        ignore_saved_user_info (boolean): True for ignore user account information (in
                                 OS keyring system) if present
    Returns:
        tuple (login_path, username, password) after the refresh occurs.
    """

    config = Config(repo)
    base_url = config.get_value(SLATEX_SECTION, "baseUrl")
    if auth_type is None:
        if not ignore_saved_user_info:
            u = config.get_value(SLATEX_SECTION, "authType")
            if u:
                auth_type = u
    if auth_type is None:
        auth_type = input(PROMPT_AUTH_TYPE)
        if not auth_type:
            auth_type = DEFAULT_AUTH_TYPE
    config.set_value(SLATEX_SECTION, "authType", auth_type)

    if username is None:
        if not ignore_saved_user_info:
            u = cast(str, config.get_value(SLATEX_SECTION, "username"))
            if u:
                username = u
    if username is None:
        username = input(PROMPT_USERNAME)
    config.set_value(SLATEX_SECTION, "username", username)

    if password is None:
        if not ignore_saved_user_info:
            p = config.get_password(base_url, username)  # type: ignore
            if p:
                password = p
    if password is None:
        password = getpass.getpass(PROMPT_PASSWORD)
        if save_password is None:
            r = input(PROMPT_CONFIRM)
            if r == "Y" or r == "y":
                save_password = True
    if save_password:
        config.set_password(base_url, username, password)  # type: ignore
    return auth_type, username, password


def exit_on_error(
    f: Callable[..., Any], msg: str, clean_up: Optional[Callable[[], None]] = None
) -> Any:
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except Exception:
            logger.error(msg)
            if clean_up is not None:
                clean_up()
            sys.exit(1)

    return wrapped


def getClient(
    repo: Repo,
    base_url: str,
    auth_type: str,
    username: str,
    password: str,
    verify: bool,
    save_password: Optional[bool] = None,
) -> SyncClient:
    logger.info(f"try to open session on {base_url} with {username}")
    client = None

    authenticator = get_authenticator_class(auth_type)()
    for i in range(MAX_NUMBER_ATTEMPTS):
        try:
            client = SyncClient(
                base_url=base_url,
                username=username,
                password=password,
                verify=verify,
                authenticator=authenticator,
            )
        except Exception as inst:
            client = None
            logger.warning(f"{inst}  : attempt # {i + 1} ")
            auth_type, username, password = refresh_account_information(
                repo,
                auth_type,
                save_password=save_password,
                ignore_saved_user_info=True,
            )
    if client is None:
        raise Exception("maximum number of authentication attempts is reached")
    return client


def update_ref(
    repo: Repo, message: str = "update_ref", git_branch: str = SYNC_BRANCH
) -> None:
    """Makes the remote pointer to point on the latest revision we have.

    This is called after a successful clone, push, new. In short when we
    are sure the remote and the local are in sync.
    """
    git = repo.git

    git.add(".")
    # with this we can have two consecutive commit with the same content
    repo.index.commit(f"{message}")
    sync_branch = repo.create_head(git_branch, force=True)
    sync_branch.commit = "HEAD"


def handle_exception(*exceptions: Type[SharelatexError]) -> Callable:
    """Decorator to handle the cli exceptions.

    Decorated
    """

    def wrapper(f: Any) -> Callable:
        """
        Wrapper.
        """

        @wraps(f)
        def inner(*args: Any, **kwargs: Any) -> Any:
            """
            inner.
            """
            try:
                r = f(*args, **kwargs)
            except exceptions as e:
                print(e.info())
                sys.exit(1)
            return r

        return inner

    return wrapper


@click.group()
def cli() -> None:
    pass


_GIT_BRANCH_OPTION = click.option(
    "--git-branch",
    "-b",
    default=SYNC_BRANCH,
    help=f"The name of a branch. We will commit the changes from Sharelatex "
    f"on this branch.\n\n Default: {SYNC_BRANCH}",
)


def log_options(function: Callable) -> Callable:
    """
    The log options.
    """
    function = click.option(
        "-v",
        "--verbose",
        count=True,
        default=2,
        help="verbose level (can be: -v, -vv, -vvv)",
    )(function)
    function = click.option("-s", "--silent", "verbose", flag_value=0)(function)
    function = click.option("--debug", "-d", "verbose", flag_value=3)(function)
    return function


def authentication_options(function: Callable) -> Callable:
    """
    authentication_options
    """
    function = click.option(
        "--auth_type",
        "-a",
        default=None,
        help="""Authentication type.""",
        type=click.Choice(list(AUTH_DICT.keys())),
    )(function)

    function = click.option(
        "--username",
        "-u",
        default=None,
        help="""Username for sharelatex server account, if username is not provided,
 it will be asked online""",
    )(function)
    function = click.option(
        "--password",
        "-p",
        default=None,
        help="""User password for sharelatex server, if password is not provided,
 it will be asked online""",
    )(function)
    function = click.option(
        "--save-password/--no-save-password",
        default=None,
        help="""Save user account information (in OS keyring system)""",
    )(function)
    function = click.option(
        "--ignore-saved-user-info",
        default=False,
        help="""Forget user account information already saved (in OS keyring system)""",
    )(function)

    return function


@cli.command(help="test log levels")
@log_options
def test(verbose: int) -> None:
    set_log_level(verbose)
    logger.debug("debug")
    logger.info("info")
    logger.error("error")
    logger.warning("warning")
    print("print")


def _sync_deleted_items(
    working_path: Path,
    remote_items: Sequence[RemoteItem],
    objects: Sequence[Path],
) -> None:
    remote_path = [Path(fd["folder_path"]).joinpath(fd["name"]) for fd in remote_items]
    for blob_path in objects:
        p_relative = blob_path.relative_to(working_path)
        # check the path and all of its parents dir
        if p_relative not in remote_path:
            logger.debug(f"delete {blob_path}")
            if blob_path.is_dir():
                blob_path.rmdir()
            else:
                Path.unlink(blob_path)


def _get_datetime_from_git(
    repo: Repo, branch: str, files: Sequence[Path], working_path: Path
) -> Mapping[str, datetime.datetime]:
    datetimes_dict = {}
    for p in files:
        commits = repo.iter_commits(branch)
        p_relative = p.relative_to(working_path)
        if not str(p_relative).startswith(".git"):
            if p not in datetimes_dict:
                for c in commits:
                    re = repo.git.show("--pretty=", "--name-only", c.hexsha)
                    if re != "":
                        commit_file_list = re.split("\n")
                        for cf in commit_file_list:
                            if cf not in datetimes_dict:
                                datetimes_dict[cf] = c.authored_datetime
                        if p in datetimes_dict:
                            break
    return datetimes_dict


def _sync_remote_files(
    client: SyncClient,
    project_id: str,
    working_path: Path,
    remote_items: Sequence[RemoteItem],
    datetimes_dict: Mapping[str, datetime.datetime],
) -> None:
    remote_files = (item for item in remote_items if item["type"] == "file")
    # TODO: build the list of file to download and then write them in a second step
    logger.debug("check if remote files are newer that locals")
    for remote_file in remote_files:
        need_to_download = False
        local_path = working_path.joinpath(remote_file["folder_path"]).joinpath(
            remote_file["name"]
        )
        relative_path = str(
            Path(remote_file["folder_path"]).joinpath(remote_file["name"])
        )
        if local_path.is_file():
            relative_path_for_dict = relative_path.replace(os.path.sep, "/")
            if relative_path_for_dict in datetimes_dict:
                local_time = datetimes_dict[relative_path_for_dict]
            else:
                local_time = datetime.datetime.fromtimestamp(
                    local_path.stat().st_mtime, datetime.timezone.utc
                )
            remote_time = dateutil.parser.parse(remote_file["created"])
            logger.debug(f"local time for {local_path} : {local_time}")
            logger.debug(f"remote time for {local_path} : {remote_time}")
            if local_time < remote_time:
                need_to_download = True
        else:
            need_to_download = True
            remote_time = datetime.datetime.now(datetime.timezone.utc)
        if need_to_download:
            logger.info(f"download from server file to update {local_path}")
            client.get_file(project_id, remote_file["_id"], dest_path=str(local_path))
            # set local time for downloaded file to remote_time
            if local_path.is_file():
                os.utime(local_path, (remote_time.timestamp(), remote_time.timestamp()))


def _sync_remote_docs(
    client: SyncClient,
    project_id: str,
    working_path: Path,
    remote_items: Sequence[RemoteItem],
    update_data: UpdateDatum,
    datetimes_dict: Mapping[str, datetime.datetime],
) -> None:
    remote_docs = (item for item in remote_items if item["type"] == "doc")
    logger.debug("check if remote documents are newer that locals")
    remote_time = datetime.datetime.now(datetime.timezone.utc)
    for remote_doc in remote_docs:
        doc_id = remote_doc["_id"]
        need_to_download = False
        local_path = working_path.joinpath(remote_doc["folder_path"]).joinpath(
            remote_doc["name"]
        )
        relative_path = str(
            Path(remote_doc["folder_path"]).joinpath(remote_doc["name"])
        )
        if local_path.is_file():
            relative_path_for_dict = relative_path.replace(os.path.sep, "/")
            if relative_path_for_dict in datetimes_dict:
                local_time = datetimes_dict[relative_path_for_dict]
            else:
                local_time = datetime.datetime.fromtimestamp(
                    local_path.stat().st_mtime, datetime.timezone.utc
                )
            updates = [
                update["meta"]["end_ts"]
                for update in update_data["updates"]
                if doc_id in update["docs"]
            ]
            if len(updates) > 0:
                remote_time = datetime.datetime.fromtimestamp(
                    updates[0] / 1000, datetime.timezone.utc
                )
                logger.debug(f"local time for {local_path} : {local_time}")
                logger.debug(f"remote time for {local_path} : {remote_time}")
                if local_time < remote_time:
                    need_to_download = True
            # elif not local_path.is_file():
            #     remote_time = datetime.datetime.now(datetime.timezone.utc)
        else:
            logger.debug(f"local path {local_path} is missing, need to download")
            need_to_download = True
            remote_time = datetime.datetime.now(datetime.timezone.utc)
        if need_to_download:
            logger.info(f"download from server file to update {local_path}")
            client.get_document(project_id, doc_id, dest_path=str(local_path))
            # Set local time for downloaded document to remote_time
            if local_path.is_file():
                os.utime(local_path, (remote_time.timestamp(), remote_time.timestamp()))


def _pull(repo: Repo, client: SyncClient, project_id: str, git_branch: str) -> None:
    # attempt to "merge" the remote and the local working copy

    git = repo.git
    active_branch = repo.active_branch.name
    git.checkout(git_branch)
    working_path = Path(repo.working_tree_dir)
    logger.debug("find last commit using remote server")
    # for optimization purpose
    commit = None
    for commit in repo.iter_commits():
        if commit.message in COMMIT_MESSAGES:
            logger.debug(f"find this : {commit.message} -- {commit.hexsha}")
            break
    if commit is None:
        raise Exception(
            "Could not find any commit with a commit message of " + str(COMMIT_MESSAGES)
        )
    logger.debug(
        f"commit as reference for upload updates: {commit.message} -- {commit.hexsha}"
    )
    # mode détaché
    git.checkout(commit)

    try:
        # etat du serveur actuel
        data = client.get_project_data(project_id)
        remote_items = [item for item in walk_project_data(data)]
        # état (supposé) du serveur la dernière fois qu'on s'est synchronisé
        # on ne prend en compte que les fichier trackés par git
        # https://gitpython.readthedocs.io/en/stable/tutorial.html#the-tree-object
        objects = [Path(b.abspath) for b in repo.head.commit.tree.traverse()]
        objects.reverse()

        datetimes_dict = _get_datetime_from_git(repo, git_branch, objects, working_path)

        _sync_deleted_items(working_path, remote_items, objects)

        _sync_remote_files(
            client, project_id, working_path, remote_items, datetimes_dict
        )

        update_data = client.get_project_update_data(project_id)
        _sync_remote_docs(
            client,
            project_id,
            working_path,
            remote_items,
            update_data,
            datetimes_dict,
        )
        # TODO reset en cas d'erreur ?
        # on se place sur la branche de synchro
        git.checkout(git_branch)
    except Exception as e:
        # hard reset ?
        git.reset("--hard")
        git.checkout(active_branch)
        raise e
    if repo.is_dirty(index=True, working_tree=True, untracked_files=True):
        diff_index = repo.index.diff(None)
        logger.debug(
            f"""Modified files in server :
            {[d.a_path for d in diff_index.iter_change_type("M")]}"""
        )
        logger.debug(
            f"""New files in server :
            {[d.a_path for d in diff_index.iter_change_type("A")]}"""
        )
        logger.debug(
            f"""deleted files in server :
            {[d.a_path for d in diff_index.iter_change_type("D")]}"""
        )
        logger.debug(
            f"""renamed files in server :
            {[d.a_path for d in diff_index.iter_change_type("R")]}"""
        )
        logger.debug(
            f"""Path type changed in server:
            {[d.a_path for d in diff_index.iter_change_type("T")]}"""
        )
        update_ref(repo, message=COMMIT_MESSAGE_PREPULL, git_branch=git_branch)
    git.checkout(active_branch)
    git.merge(git_branch)


@cli.command()
@click.argument("project_id", default="")
@authentication_options
@log_options
def compile(
    project_id: str,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
) -> None:
    """
    Compile the remote version of a project
    """
    set_log_level(verbose)
    repo = Repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = exit_on_error(getClient, AUTHENTICATION_FAILED)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    response = client.compile(project_id)
    logger.debug(response)


@cli.command()
@click.argument("email", default="")
@click.option("--project_id", default=None)
@click.option(
    "--can-edit/--read-only",
    default=True,
    help="""Authorize user to edit the project or not""",
)
@authentication_options
@log_options
def share(
    project_id: str,
    email: str,
    can_edit: bool,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
) -> None:
    """
    Send an invitation to share (edit/view) a project
    """
    set_log_level(verbose)
    repo = Repo()
    base_url, project_id, https_cert_check = refresh_project_information(
        repo, project_id=project_id
    )
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = exit_on_error(getClient, AUTHENTICATION_FAILED)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    response = client.share(project_id, email, can_edit)
    logger.debug(response)


@cli.command(
    help=f"""Pull the files from sharelatex.

    In the current repository, it works as follows:

    1. Pull in the latest version of the remote project in ``{SYNC_BRANCH}``
    respectively the given branch.\n
    2. Attempt a merge in the working branch. If the merge can't be done automatically,
       you will be required to fix the conflict manually
    """
)
@_GIT_BRANCH_OPTION
@authentication_options
@log_options
@handle_exception(RepoNotCleanError)
def pull(
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
    git_branch: str,
) -> None:
    set_log_level(verbose)

    # Fail if the repo is not clean
    repo = get_clean_repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )
    client = exit_on_error(getClient, AUTHENTICATION_FAILED)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )
    _pull(repo, client, project_id, git_branch=git_branch)


@cli.command()
@click.argument(
    "projet_url", default=""
)  # , help="The project url (https://sharelatex.irisa.fr/1234567890)")
@click.argument("directory", default="", type=click.Path(file_okay=False))
@click.option(
    "--https-cert-check/--no-https-cert-check",
    default=True,
    help="""force to check https certificate or not""",
)
@click.option(
    "--whole-project-download/--no-whole-project-download",
    default=True,
    help="""download whole project in a zip file from the server/ or download
 sequentially file by file from the server""",
)
@_GIT_BRANCH_OPTION
@authentication_options
@log_options
@handle_exception(RepoNotCleanError)
def clone(
    projet_url: str,
    directory: str,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    https_cert_check: bool,
    whole_project_download: bool,
    verbose: int,
    git_branch: str,
) -> None:
    f"""
    Get (clone) the files from sharelatex project URL and create a local git depot.

    The optional target directory will be created if it doesn't exist. The command
    fails if it already exists. Connection information can be saved in the local git
    config.

    It works as follow:

        1. Download and unzip the remote project in the target directory\n
        2. Initialize a fresh git repository\n
        3. Create an extra ``{SYNC_BRANCH}`` to keep track of the remote versions of
           the project. This branch must not be updated manually.
    """
    set_log_level(verbose)
    # TODO : robust parse regexp
    slashparts = projet_url.split("/")
    project_id = slashparts[-1]
    base_url = "/".join(slashparts[:-2])
    if base_url == "":
        raise Exception(URL_MALFORMED_ERROR_MESSAGE)
    if directory == "":
        directory_as_path = Path(os.getcwd())
        directory_as_path = Path(directory_as_path, project_id)
    else:
        directory_as_path = Path(directory)
    directory_as_path.mkdir(parents=True, exist_ok=False)

    repo = get_clean_repo(path=directory_as_path)

    base_url, project_id, https_cert_check = refresh_project_information(
        repo, base_url, project_id, https_cert_check
    )
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )

    def clean_up() -> None:
        import shutil

        shutil.rmtree(directory_as_path)

    client = exit_on_error(getClient, AUTHENTICATION_FAILED, clean_up)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    if whole_project_download:
        client.download_project(project_id, path=str(directory_as_path))
        update_ref(repo, message=COMMIT_MESSAGE_CLONE, git_branch=git_branch)
    else:
        update_ref(repo, message=COMMIT_MESSAGE_CLONE, git_branch=git_branch)
        _pull(repo, client, project_id, git_branch=git_branch)
    # TODO(msimonin): add a decent default .gitignore ?


def _upload(
    repo: Repo, client: SyncClient, project_data: ProjectData, path: str
) -> str:
    # initial factorisation effort
    path_as_path = Path(path)
    logger.debug(f"Uploading {path_as_path}")
    project_id = project_data["_id"]
    folder_id = client.check_or_create_folder(project_data, str(path_as_path.parent))
    p = Path(repo.working_dir).joinpath(path_as_path)
    client.upload_file(project_id, folder_id, str(p))
    return folder_id


def _push(
    force: bool,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
    git_branch: str,
) -> None:
    set_log_level(verbose)

    def _delete(c_client: SyncClient, c_project_data: ProjectData, path: str) -> None:
        # initial factorisation effort
        path_as_path = Path(path)
        logger.debug(f"Deleting {path_as_path}")
        project_id = c_project_data["_id"]
        entities = walk_project_data(
            c_project_data,
            lambda x: Path(x["folder_path"]) == path_as_path.parent
            and x["name"] == path_as_path.name,  # noqa: W503
        )
        # there should be one
        entity = next(entities)
        if entity["type"] == "doc":
            c_client.delete_document(project_id, entity["_id"])
        elif entity["type"] == "file":
            c_client.delete_file(project_id, entity["_id"])

    repo = get_clean_repo()
    base_url, project_id, https_cert_check = refresh_project_information(repo)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, ignore_saved_user_info
    )

    client = exit_on_error(getClient, AUTHENTICATION_FAILED)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    if not force:
        _pull(repo, client, project_id, git_branch=git_branch)
    config = Config(repo)
    # prevent git returning quoted path in diff when file path has unicode char
    config.set_value("core", "quotepath", "off")
    master_commit = repo.commit("HEAD")
    sync_commit = repo.commit(git_branch)
    diff_index = sync_commit.diff(master_commit)

    project_data = client.get_project_data(project_id)
    folders = {f["folder_id"] for f in walk_folders(project_data)}

    logger.debug("Modify files to upload :")
    for d in diff_index.iter_change_type("M"):
        if _upload(repo, client, project_data, d.a_path) not in folders:
            project_data = client.get_project_data(project_id)
            folders = {f["folder_id"] for f in walk_folders(project_data)}

    logger.debug("new files to upload :")
    for d in diff_index.iter_change_type("A"):
        if _upload(repo, client, project_data, d.a_path) not in folders:
            project_data = client.get_project_data(project_id)
            folders = {f["folder_id"] for f in walk_folders(project_data)}

    logger.debug("delete files :")
    for d in diff_index.iter_change_type("D"):
        _delete(client, project_data, d.a_path)

    logger.debug("rename files :")
    for d in diff_index.iter_change_type("R"):
        # git mv a b
        # for us this corresponds to
        # 1) deleting the old one (a)
        # 2) creating the new one (b)
        _delete(client, project_data, d.a_path)
        if _upload(repo, client, project_data, d.b_path) not in folders:
            project_data = client.get_project_data(project_id)
            folders = {f["folder_id"] for f in walk_folders(project_data)}
    logger.debug("Path type changes :")
    for d in diff_index.iter_change_type("T"):
        # This one is maybe
        # 1) deleting the old one (a)
        # 2) creating the new one (b)
        _delete(client, project_data, d.a_path)
        if _upload(repo, client, project_data, d.b_path) not in folders:
            project_data = client.get_project_data(project_id)
            folders = {f["folder_id"] for f in walk_folders(project_data)}
    if repo.is_dirty(index=True, working_tree=True, untracked_files=True):
        update_ref(repo, message=COMMIT_MESSAGE_PUSH, git_branch=git_branch)


@cli.command()
@click.option("--force", is_flag=True, help="Force push", default=False)
@_GIT_BRANCH_OPTION
@click.option("--force", is_flag=True, help="Force push")
@authentication_options
@log_options
@handle_exception(RepoNotCleanError)
def push(
    force: bool,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
    git_branch: str,
) -> None:
    """Synchronize the local copy with the remote version.

    This works as follows:

    1. The remote version is pulled (see the :program:`pull` command)\n
    2. After the merge succeed, the merged version is uploaded back to the remote
    server.\n
       Note that only the files that have changed (modified/added/removed) will
       be uploaded.
    """
    _push(
        force,
        auth_type,
        username,
        password,
        save_password,
        ignore_saved_user_info,
        verbose,
        git_branch=git_branch,
    )


@cli.command()
@click.argument("projectname")
@click.argument("base_url")
@click.option(
    "--https-cert-check/--no-https-cert-check",
    default=True,
    help="""force to check https certificate or not""",
)
@click.option(
    "--whole-project-upload/--no-whole-project-upload",
    default=True,
    help="""upload whole project in a zip file to the server/ or
upload sequentially file by file to the server""",
)
@click.option(
    "--rate-max-uploads-by-sec",
    default=0.4,
    help="""number of max uploads
 by seconds to the server (some servers limit the this rate),
 useful with --no-whole-project-upload""",
)
@_GIT_BRANCH_OPTION
@authentication_options
@log_options
@handle_exception(RepoNotCleanError)
def new(
    projectname: str,
    base_url: str,
    https_cert_check: bool,
    whole_project_upload: bool,
    rate_max_uploads_by_sec: float,
    auth_type: str,
    username: Optional[str],
    password: Optional[str],
    save_password: Optional[bool],
    ignore_saved_user_info: bool,
    verbose: int,
    git_branch: str,
) -> None:
    """
    Upload the current directory as a new sharelatex project.

    This literally creates a new remote project in sync with the local version.
    """
    set_log_level(verbose)
    repo = get_clean_repo()

    refresh_project_information(repo, base_url, "NOT SET", https_cert_check)
    auth_type, username, password = refresh_account_information(
        repo, auth_type, username, password, save_password, True
    )
    client = exit_on_error(getClient, AUTHENTICATION_FAILED)(
        repo,
        base_url,
        auth_type,
        username,
        password,
        https_cert_check,
        save_password,
    )

    iter_file = repo.tree().traverse()

    with tempfile.TemporaryDirectory() as tmp:
        archive_name = os.path.join(tmp, f"{projectname}.zip")

        with ZipFile(archive_name, "w") as z:
            for f in iter_file:
                logger.debug(f"Adding {f.path} to the archive {archive_name}")
                z.write(f.path)
                if not whole_project_upload and Path(f.path).is_file():
                    logger.debug("sequential upload, only one file in zip")
                    break
        response = client.upload(archive_name)
        project_id = response["project_id"]
        logger.info(f"Successfully uploaded {projectname} [{project_id}]")
        try:
            refresh_project_information(repo, base_url, project_id, https_cert_check)
            if not whole_project_upload:
                iter_file = repo.tree().traverse()
                project_data = client.get_project_data(project_id)
                upload_rate_limiter = RateLimiter(rate_max_uploads_by_sec)
                folders = {f["folder_id"] for f in walk_folders(project_data)}
                for f in iter_file:
                    if Path(f.path).is_file():
                        if _upload(repo, client, project_data, f.path) not in folders:
                            project_data = client.get_project_data(project_id)
                            folders = {
                                f["folder_id"] for f in walk_folders(project_data)
                            }
                        upload_rate_limiter.event_inc()
            update_ref(repo, message=COMMIT_MESSAGE_UPLOAD, git_branch=git_branch)
        except Exception as inst:
            logger.debug(f"delete failed project {project_id} into server ")
            client.delete(project_id, forever=True)
            raise inst
