import json
import logging
import os
import pickle
import re
import threading
import time
import urllib.parse
import uuid
import zipfile
from pathlib import Path
from typing import (
    Any,
    Callable,
    Generator,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)
from typing import cast as typing_cast

import filetype
import requests
from appdirs import user_data_dir

# try to find CAS form
from lxml import html
from socketIO_client import BaseNamespace, SocketIO

from .__version__ import __version__

try:
    from typing import Literal, TypedDict
except ImportError:
    from typing_extensions import Literal, TypedDict  # type: ignore

logger = logging.getLogger(__name__)


class ProjectData(TypedDict):
    """
    Project data.
    """

    _id: str
    rootFolder: str
    name: str


class UpdateMeta(TypedDict):
    """
    Update.
    """

    end_ts: int


class Update(TypedDict):
    """
    Update.
    """

    docs: Sequence[str]
    meta: UpdateMeta


class UpdateDatum(TypedDict):
    """
    Update datum.
    """

    updates: Sequence[Update]


def set_logger(new_logger: logging.Logger) -> None:
    """
    set logger.
    """
    global logger
    logger = new_logger


BASE_URL = "https://overleaf.irisa.fr"
USER_AGENT = f"python-sharelatex {__version__}"


class SharelatexError(Exception):
    """
    Base class for the errors here.
    """

    pass


class CompilationError(SharelatexError):
    """
    CompilationError
    """

    def __init__(self, json_status: str):
        super().__init__("Compilation failed", json_status)


class FolderRep(TypedDict):
    """
    Folder
    """

    name: str
    _id: str
    fileRefs: Sequence[str]
    docs: Sequence[str]
    folders: Sequence["FolderRep"]


def walk_project_data(
    project_data: ProjectData, predicate: Callable[[Any], bool] = lambda x: True
) -> Any:
    """Iterate on the project entities (folders, files).

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`
        predicate (lambda): Lambda to filter the entry
            an entry is a dictionary as in
            {"folder_id": <id of the current folder>,
             "folder_path": <complete path of the folder /a/folder/>,
             "name": <name of the entity>,
             "type": <type of the entity directory or file>,
             "_id" : <id of the entity>

    Returns:
        A generator for the matching entities
    """

    def _walk_project_data(current: Sequence[FolderRep], parent: str) -> Any:
        """Iterate on the project structure

        Args:
            current (dict): Current folder representation
            parent (str): Path of the parent folder
        """
        for c in current:
            if c["name"] == "rootFolder":
                folder_name = "."
            else:
                folder_name = c["name"]
            folder_path = os.path.join(parent, folder_name)
            folder_id = c["_id"]
            fd = {
                "folder_id": folder_id,
                "folder_path": folder_path,
                "name": ".",
                "type": "folder",
            }
            if predicate(fd):
                yield fd
            for f in c["fileRefs"]:
                fd = {
                    "folder_id": folder_id,
                    "folder_path": folder_path,
                    "type": "file",
                }
                fd.update(f)  # type: ignore
                if predicate(fd):
                    yield fd
            for d in c["docs"]:
                fd = {"folder_id": folder_id, "folder_path": folder_path, "type": "doc"}
                fd.update(d)  # type: ignore
                if predicate(fd):
                    yield fd
            if len(c["folders"]) > 0:
                yield from _walk_project_data(c["folders"], folder_path)

    return _walk_project_data(project_data["rootFolder"], "")  # type: ignore


class FolderData(TypedDict):
    """
    Folder.
    """

    folder_id: str


def lookup_folder(project_data: ProjectData, folder_path: str) -> FolderData:
    """Lookup a folder by its path

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`
        folder_path (str): The path of the folder. Must start with ``/``

    Returns:
        The folder id (str)

    Raises:
         StopIteration if the folder isn't found
    """
    folder_path_as_path = Path(folder_path)
    folders = walk_project_data(
        project_data, predicate=lambda x: Path(x["folder_path"]) == folder_path_as_path
    )
    return next(folders)  # type: ignore


def walk_files(project_data: ProjectData) -> Generator:
    """Iterates on the file only of a project.

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`

    Raises:
        StopIteration if the file isn't found
    """
    return walk_project_data(  # type: ignore
        project_data, lambda x: x["type"] == "file"  # type: ignore
    )  # type: ignore


def walk_folders(project_data: ProjectData) -> Generator:
    """Iterates on the folders only of a project.

    Args:
        project_data (dict): The project data as retrieved by
            :py:meth:`sharelatex.SyncClient.get_project_data`

    Raises:
        StopIteration if the file isn't found
    """
    return walk_project_data(  # type: ignore
        project_data, lambda x: x["type"] == "folder"  # type: ignore
    )  # type: ignore


def check_login_error(response: requests.Response) -> None:
    """
    Check if there's an error in the request response

    The response text is
    - HTML if the auth is successful
    - json: otherwise
        {
            "message":
            {
                "text": "Your email or password is incorrect. Please try again",
                "type": "error"
            }
        }

    Args:
        response (request response): message returned by the sharelatex server

    Raise:
        Exception with the corresponding text in the message
    """
    try:
        json = response.json()
        message = json.get("message")
        if message is None:
            return
        t = message.get("type")
        if t is not None and t == "error":
            raise Exception(message.get("text", "Unknown error"))
    except requests.exceptions.JSONDecodeError:
        # this might be a successful login here
        logger.info("no Login error message")
        pass


def get_csrf_Token(html_text: str) -> Optional[str]:
    """Retrieve csrf token from a html text page from sharelatex server.

    Args:
        html_text (str): The text from a html page of sharelatex server
    Returns:
        the csrf token (str) if found in html_text or None if not
    """
    if "csrfToken" in html_text:
        csrf_token = re.search('(?<=csrfToken = ").{36}', html_text)
        if csrf_token is not None:
            return csrf_token.group(0)
        else:
            # check is overleaf token is here
            parsed = html.fromstring(html_text)
            meta = parsed.xpath("//meta[@name='ol-csrfToken']")
            if meta:
                return typing_cast(str, meta[0].get("content"))
    return None


class Authenticator:
    """
    Authenticator
    """

    def __init__(self, session: Optional[requests.Session] = None):
        self.login_url: str = ""
        self.username: str = ""
        self.password: str = ""
        self.sid_name: str = ""
        self.verify: bool = True
        self.csrf: str = ""
        self.login_data: Mapping[str, Any] = {}
        self._session: requests.Session = typing_cast(requests.Session, session)

    @property
    def session(self) -> requests.Session:
        """
        Session.
        """
        if self._session is None:
            self._session = requests.session()
        return self._session

    @session.setter
    def session(self, session: requests.Session) -> None:
        self._session = session

    def authenticate(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path: str = "/login",
        sid_name: str = "sharelatex.sid",
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Authenticate.

        Returns:
            Tuple of login data and the cookie (containing the session id)
            These two information can be used to forge further requests
        """
        raise NotImplementedError


class DefaultAuthenticator(Authenticator):
    """
    Default authenticator.
    """

    def __init__(
        self,
    ) -> None:
        """Use the default login form of the community edition.

        Args:
            login_url: full url where the login form can be found
            username: username to use (an email address)
            password: the password to use
            verify: True to enable SSL verification (use False for self-signed
                testing instance)
        """
        super().__init__()

    def authenticate(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path: str = "/login",
        sid_name: str = "sharelatex.sid",
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        self.login_url = urllib.parse.urljoin(base_url, login_path)
        self.username = username
        self.password = password
        self.verify = verify
        self.sid_name = sid_name

        r = self.session.get(self.login_url, verify=self.verify)

        _csrf = get_csrf_Token(r.text)
        if _csrf is None:
            raise Exception(f"We could not find the CSRF in {self.login_url}")
        self.csrf = _csrf
        self.login_data = dict(
            email=self.username,
            password=self.password,
            _csrf=self.csrf,
        )
        logger.debug("try login")
        _r = self.session.post(self.login_url, data=self.login_data, verify=self.verify)
        _r.raise_for_status()
        check_login_error(_r)
        _csrf = get_csrf_Token(_r.text)
        if _csrf is None:
            raise Exception(f"We could not find the CSRF in {self.login_url}")
        login_data = dict(email=self.username, _csrf=_csrf)
        return login_data, {self.sid_name: _r.cookies[self.sid_name]}


class CommunityAuthenticator(DefaultAuthenticator):
    """
    Community authenticator.
    """

    pass


class LegacyAuthenticator(DefaultAuthenticator):
    """
    Legacy authenticator
    """

    def authenticate(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path: str = "/login",
        sid_name: str = "sharelatex.sid",
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        """
        Authenticate.
        """
        self.login_url = urllib.parse.urljoin(base_url, login_path)
        self.username = username
        self.password = password
        self.verify = verify
        self.sid_name = sid_name

        r = self.session.get(self.login_url, verify=self.verify)
        _csrf = get_csrf_Token(r.text)
        if _csrf is None:
            raise Exception(f"We could not find the CSRF in {self.login_url}")
        self.csrf = _csrf
        self.login_data = dict(
            email=self.username,
            password=self.password,
            _csrf=self.csrf,
        )
        logger.debug("try login")
        _r = self.session.post(self.login_url, data=self.login_data, verify=self.verify)
        _r.raise_for_status()
        check_login_error(_r)
        login_data = dict(email=self.username, _csrf=self.csrf)
        return login_data, {self.sid_name: _r.cookies[self.sid_name]}


class GitlabAuthenticator(DefaultAuthenticator):
    """We use Gitlab as authentication backend (using OAUTH2).

    In this context, the login page redirect to the login page of gitlab(inria),
    which in turn redirect to Overleaf. upon success, we get back the project
    page where the csrf token can be found

    More precisely there are two login forms available
        - one for LDAP account (inria)
        - one for Local account (external user)
    As a consequence we adopt the following strategy to authenticate:
    First we attempt to log with the LDAP form if that fails for any reason
    we try to log in with the local form.
    """

    def __init__(self) -> None:
        super().__init__()

    def _login_data_ldap(self, username: str, password: str) -> Mapping[str, str]:
        return {"username": username, "password": password}

    def _login_data_local(self, username: str, password: str) -> Mapping[str, str]:
        return {"user[login]": username, "user[password]": password}

    def _get_login_forms(self) -> Any:
        r = self.session.get(self.login_url, verify=self.verify)
        gitlab_form = html.fromstring(r.text)
        if len(gitlab_form.forms) < 2:
            raise ValueError("Expected 2 authentication forms")
        ldap, local = gitlab_form.forms
        return r.url, ldap, local

    def authenticate(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool = True,
        login_path: str = "/auth/callback/gitlab",
        sid_name: str = "sharelatex.sid",
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        """
        Authenticate.
        """
        self.login_url = urllib.parse.urljoin(base_url, login_path)
        self.username = username
        self.password = password
        self.verify = verify
        self.sid_name = sid_name
        try:
            url, ldap_form, _ = self._get_login_forms()
            return self._authenticate(url, ldap_form, self._login_data_ldap)
        except Exception as e:
            logger.info(
                f"Unable to authenticate with LDAP for {self.username}, "
                f"continuing with local account ( {e} )"
            )

        try:
            url, _, local_form = self._get_login_forms()
            return self._authenticate(url, local_form, self._login_data_local)
        except Exception as e:
            logger.info(
                f"Unable to authenticate with local account for {self.username}, "
                f"leaving ({e})"
            )

        raise ValueError(f"Authentication failed for {self.username}")

    def _authenticate(
        self,
        url: str,
        html_form: Any,  # parsed html
        login_data_fnc: Callable[[str, str], Mapping[str, str]],
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:

        if not any(
            field in html_form.fields.keys()
            for field in ["execution", "authenticity_token"]
        ):
            raise ValueError("Executed fields not found in authentication form")

        login_data = {name: value for name, value in html_form.form_values()}
        login_data.update(login_data_fnc(self.username, self.password))
        post_url = urllib.parse.urljoin(url, html_form.action)
        _r = self.session.post(post_url, data=login_data, verify=self.verify)
        _r.raise_for_status()
        # beware that here we're redirected to a redirect page
        # (not on sharelatex directly...)
        # This look like this
        # <h3 class="page-title">Redirecting</h3>
        #   <div>
        #       <a href="redirect_url"> Click here to redirect to
        #       [..]
        #
        # In this case, let's simply "click" on the link
        redirect_html = html.fromstring(_r.text)
        redirect_url = redirect_html.xpath("//a")[0].get("href")
        _r = self.session.get(redirect_url, verify=self.verify)
        _r.raise_for_status()
        check_login_error(_r)
        _csrf = get_csrf_Token(_r.text)
        if _csrf is None:
            raise Exception(f"We could not find the CSRF in {redirect_url}")
        logger.info("Logging successful")
        login_data = dict(email=self.username, _csrf=_csrf)
        return login_data, {self.sid_name: _r.cookies[self.sid_name]}


AUTH_DICT = {
    "gitlab": GitlabAuthenticator,
    "community": CommunityAuthenticator,
    "legacy": LegacyAuthenticator,
}


def get_authenticator_class(auth_type: str) -> Type[Authenticator]:
    """
    Return the authenticator.
    """
    auth_type = auth_type.lower()
    try:
        return AUTH_DICT[auth_type]
    except KeyError:
        raise ValueError(f"auth_type must be in found {list(AUTH_DICT.keys())}")


class SyncClient:
    """
    Sync client
    """

    def __init__(
        self,
        *,
        base_url: str = BASE_URL,
        username: str = "",
        password: str = "",
        verify: bool = True,
        authenticator: Optional[Authenticator] = None,
    ) -> None:
        """Creates the client.

        This mimics the browser behaviour when logging in.


        Args:
            base_url (str): Base url of the sharelatex server
            username (str): Username of the user (the email)
            password (str): Password of the user
            verify (bool): True iff SSL certificates must be verified
            authenticator: Authenticator to use

        """
        if base_url == "":
            raise Exception("project_url is not well formed or missing")
        self.base_url = base_url
        self.verify = verify

        # Used in _get, _post... to add common headers
        self.headers = {"user-agent": USER_AGENT}

        # build the client and login
        self.client = requests.session()
        self.client.verify = verify
        if authenticator is None:
            # build a default authenticator based on the
            # given credentials
            authenticator = DefaultAuthenticator()

        # set the session to use for authentication
        authenticator.session = self.client

        expire_time = 1000  # seconds
        update_need = False

        cache_dir = Path(user_data_dir("python-sharelatex"))
        cache_dir.mkdir(parents=True, exist_ok=True)
        datafile = cache_dir / Path("session_cache")
        if datafile.is_file():
            with open(datafile, "rb") as f:
                data = pickle.load(f)
        else:
            data = {}
        k = base_url + "_" + username
        if k in data:
            session_data, data_time = data[k]
            current_time = time.time()
            if current_time - data_time < expire_time:
                self.login_data, self.cookie = session_data
            else:
                update_need = True
        else:
            update_need = True
        if update_need:
            self.login_data, self.cookie = authenticator.authenticate(
                base_url=self.base_url,
                username=username,
                password=password,
                verify=self.verify,
            )
            data_time = time.time()
            data[k] = ((self.login_data, self.cookie), data_time)
            with open(datafile, "wb") as f:
                pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)

    def get_project_data(self, project_id: str) -> ProjectData:
        """Get the project hierarchy and some metadata.

        This mimics the browser behaviour when opening the project editor. This
        will open a websocket connection to the server to get the information.

        Args:
            project_id (str): The id of the project
        """

        url = f"{self.base_url}/project/{project_id}"

        # use thread local storage to pass the project data
        storage = threading.local()
        storage.is_data = False

        class Namespace(BaseNamespace):
            """
            Namespace.
            """

            def on_connect(self) -> None:
                """
                On connect.
                """
                logger.debug("[Connected] Yeah !!")

            def on_reconnect(self) -> None:
                """
                On re.
                """
                logger.debug("[Reconnected] re-Yeah !!")

            def on_disconnect(self) -> None:
                """
                On dis.
                """
                logger.debug("[Disconnected]  snif!  ")

        def on_joint_project(*args: Any) -> None:
            """
            on_joint_project
            """
            storage.project_data = args[1]
            storage.is_data = True

        def on_connection_rejected(*args: Any) -> None:
            """
            on_connection_rejected
            """
            logger.debug("[connectionRejected]  oh !!!")

        headers = {"Referer": url}
        headers.update(self.headers)
        with SocketIO(
            self.base_url,
            verify=self.verify,
            Namespace=Namespace,
            cookies=self.cookie,
            headers=headers,
        ) as socketIO:

            def on_connection_accepted(*args: Any) -> None:
                """
                on_connection_accepted
                """
                logger.debug("[connectionAccepted]  Waoh !!!")
                socketIO.emit(
                    "joinProject", {"project_id": project_id}, on_joint_project
                )

            socketIO.on("connectionAccepted", on_connection_accepted)
            socketIO.on("connectionRejected", on_connection_rejected)
            while not storage.is_data:
                logger.debug("[socketIO] wait for project data")
                socketIO.wait(0.1)
            logger.debug("[socketIO] wait for project data finish !")
        # NOTE(msimonin): Check return type
        # this must be a valid dict (e.g., not None)
        return typing_cast(ProjectData, storage.project_data)

    def _request(
        self,
        verb: Literal["POST", "GET", "DELETE"],
        url: str,
        *args: Any,
        **kwargs: Any,
    ) -> requests.Response:
        headers = kwargs.get("headers", {})
        headers.update(self.headers)
        kwargs["headers"] = headers
        cookies = kwargs.get("cookies", {})
        cookies.update(self.cookie)
        kwargs["cookies"] = cookies
        r = self.client.request(verb, url, *args, **kwargs)
        r.raise_for_status()
        return r

    def _get(self, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, *args, **kwargs)

    def _post(self, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        return self._request("POST", url, *args, **kwargs)

    def _delete(self, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        return self._request("DELETE", url, *args, **kwargs)

    def get_projects_data(self) -> list:
        """Get list of projects data.
        Every element of return list is a dictionary of some data of a project
        """
        r = self._get(url=f"{self.base_url}/project/", verify=self.verify)
        parsed = html.fromstring(r.content)
        elements = parsed.xpath("//meta[@name='ol-projects']")
        return list(json.loads(elements[0].get("content")))

    def get_project_update_data(self, project_id: str) -> UpdateDatum:
        """Get update (history) data of a project.


        Args:
            project_id (str): The id of the project to download

        Raises:
            Exception if the project update data can't be downloaded.
        """
        url = f"{self.base_url}/project/{project_id}/updates"
        logger.info(f"Downloading update data for {project_id}")
        r = self._get(url)
        r.raise_for_status()
        return typing_cast(UpdateDatum, r.json())

    def download_project(
        self, project_id: str, *, path: str = ".", keep_zip: bool = False
    ) -> None:
        """Download and unzip the project.

        Beware that this will overwrite any existing project file under path.

        Args:
            project_id (str): The id of the project to download
            path (Path): A valid path where the files will be saved

        Raises:
            Exception if the project can't be downloaded/unzipped.
        """
        url = f"{self.base_url}/project/{project_id}/download/zip"
        r = self._get(url, stream=True)
        logger.info(f"Downloading {project_id} in {path}")
        target_dir = Path(path)
        target_path = Path(target_dir, f"{project_id}.zip")
        with open(str(target_path), "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        logger.info(f"Unzipping {project_id} in {path}")
        with zipfile.ZipFile(target_path) as zip_file:
            zip_file.extractall(path=path)

        if not keep_zip:
            target_path.unlink()

    def post_chat_message(self, project_id: str, message: str) -> bool:
        """Post a message in chat channel of a project.

        Args:
            project_id (str): The id of the project where post message
            message (str): the message to post from current user connected

        Raises:
            Exception if the post failed
        Returns:
            a bool True if message post has succeeded
        """
        data = {"content": message, "_csrf": self.login_data["_csrf"]}
        url = f"{self.base_url}/project/{project_id}/messages"
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        return r.status_code == 204

    def get_chats_messages(self, project_id: str) -> Any:
        """Get a list of messages in chat channel of a project.

        Args:
            project_id (str): The id of the project that have chat messages

        Raises:
            Exception if the get failed
        Returns:
            a list of dictionaries contains messages information: such content,
            timestamp of posted message, poster(user) information dictionary
        """
        url = f"{self.base_url}/project/{project_id}/messages"
        r = self._get(url, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def get_document(
        self, project_id: str, doc_id: str, dest_path: Optional[str] = None
    ) -> Union[bool, str]:
        """Get a document from a project .

        This mimics the browser behavior when opening the project editor. This
        will open a websocket connection to the server to get the information.

        Args:
            project_id (str): The id of the project
            doc_id (str): The id of the doc
            dest_path (str): the path to write the document, must be None if
                output is a string with the contents of document

        Returns:
            A string corresponding to the document if dest_path is None
            or True if dest_path is correctly written
        """

        url = f"{self.base_url}/project/{project_id}"

        # use thread local storage to pass the project data
        storage = threading.local()
        storage.is_data = False

        class Namespace(BaseNamespace):
            """
            Namespace.
            """

            def on_connect(self) -> None:
                """
                on_connect.
                """
                logger.debug("[Connected] Yeah !!")

            def on_reconnect(self) -> None:
                """
                on_reconnect.
                """
                logger.debug("[Reconnected] re-Yeah !!")

            def on_disconnect(self) -> None:
                """
                on_disconnect.
                """
                logger.debug("[Disconnected]  snif!  ")

        def on_connection_rejected(*args: Any) -> None:
            """
            on_connection_rejected.
            """
            logger.debug("[connectionRejected]  oh !!!")

        headers = {"Referer": url}
        headers.update(self.headers)
        with SocketIO(
            self.base_url,
            verify=self.verify,
            Namespace=Namespace,
            cookies=self.cookie,
            headers=headers,
        ) as socketIO:

            def on_joint_doc(*args: Any) -> None:
                """
                on_joint_doc.
                """
                # transform list of str (lines) as bytes for finally decode as
                # utf-8 list of str
                storage.doc_data = [
                    bytes(ord(c) for c in line).decode("utf-8") for line in args[1]
                ]
                storage.is_data = True

            def on_joint_project(*args: Any) -> None:
                """
                on_joint_project.
                """
                storage.project_data = args[1]
                socketIO.emit("joinDoc", doc_id, {"encodeRanges": True}, on_joint_doc)

            def on_connection_accepted(*args: Any) -> None:
                """
                on_connection_accepted.
                """
                logger.debug("[connectionAccepted]  Waoh !!!")
                socketIO.emit(
                    "joinProject", {"project_id": project_id}, on_joint_project
                )

            socketIO.on("connectionAccepted", on_connection_accepted)
            socketIO.on("connectionRejected", on_connection_rejected)
            while not storage.is_data:
                logger.debug("[socketIO] wait for doc data")
                socketIO.wait(0.1)
            logger.debug("[socketIO] wait for doc data finish !")
        # NOTE(msimonin): Check return type
        if dest_path is None:
            return "\n".join(storage.doc_data)
        else:
            dest_path_as_path = Path(dest_path)
            dest_path_as_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path_as_path, "w") as f:
                f.write("\n".join(storage.doc_data))
            return True

    def get_file(
        self, project_id: str, file_id: str, dest_path: Optional[str] = None
    ) -> Union[str, bool]:
        """Get an individual file (e.g image).

        Args:
            project_id (str): The project id of the project where the file is
            file_id (str): The file id
            dest_path (str): the path to write the document, must be None if
                output is a string with the contents of document

        Returns:
            A string corresponding to the file if dest_path is None
            or True if dest_path is correctly written

        Raises:
            Exception if the file can't be downloaded
        """
        url = f"{self.base_url}/project/{project_id}/file/{file_id}"
        r = self._get(url, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type
        if dest_path is None:
            return r.content.decode()
        else:
            dest_path_as_path = Path(dest_path)
            dest_path_as_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path_as_path, "bw") as f:
                f.write(r.content)
            return True

    def delete_file(self, project_id: str, file_id: str) -> requests.Response:
        """Delete a single file (e.g image).

        Args:
            project_id (str): The project id of the project where the file is
            file_id (str): The file id

        Returns:
            requests response

        Raises:
            Exception if the file can't be deleted
        """
        url = f"{self.base_url}/project/{project_id}/file/{file_id}"
        r = self._delete(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type
        return r

    def delete_document(self, project_id: str, doc_id: str) -> requests.Response:
        """Delete a single document (e.g tex file).

        Args:
            project_id (str): The project id of the project where the document is
            doc_id (str): The document id

        Returns:
            requests response

        Raises:
            Exception if the document can't be deleted
        """
        url = f"{self.base_url}/project/{project_id}/doc/{doc_id}"
        r = self._delete(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type

        return r

    def delete_folder(self, project_id: str, folder_id: str) -> requests.Response:
        """Delete a single folder (with all data inside).

        Args:
            project_id (str): The project id of the project where the folder is
            folder_id (str): The folder id

        Returns:
            requests response

        Raises:
            Exception if the folder can't be deleted
        """
        url = f"{self.base_url}/project/{project_id}/folder/{folder_id}"
        r = self._delete(url, data=self.login_data, verify=self.verify)
        r.raise_for_status()
        # TODO(msimonin): return type

        return r

    def upload_file(self, project_id: str, folder_id: str, c_path: str) -> Any:
        """Upload a file to sharelatex.

        Args:
            project_id (str): The project id
            folder_id (str): The parent folder
            path_as_path (str): Local path to the file

        Returns:
            requests response

        Raises:
            Exception if the file can't be uploaded
        """
        url = f"{self.base_url}/project/{project_id}/upload"
        path_as_path = Path(c_path)
        # TODO(msimonin): handle correctly the content-type
        mime = filetype.guess(str(path_as_path))
        if not mime:
            mime = "text/plain"
        files = {"qqfile": (path_as_path.name, open(path_as_path, "rb"), mime)}
        params = {
            "folder_id": folder_id,
            "_csrf": self.login_data["_csrf"],
            "qquid": str(uuid.uuid4()),
            "qqfilename": path_as_path.name,
            "qqtotalfilesize": os.path.getsize(path_as_path),
        }
        r = self._post(url, params=params, files=files, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if not response["success"]:
            raise Exception(f"Uploading {path_as_path} fails")
        return response

    def create_folder(self, project_id: str, parent_folder: str, name: str) -> Any:
        """Create a folder on sharelatex.

        Args:
            project_id (str): The project id of the project to create the folder in
            parent_folder (str): The id of the folder to create the folder in
            name (str): Name of the folder

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
            Something wrong with sharelatex
            - 500 server error
            - 400 the folder already exists
        """
        url = f"{self.base_url}/project/{project_id}/folder"
        data = {
            "parent_folder_id": parent_folder,
            "_csrf": self.login_data["_csrf"],
            "name": name,
        }
        logger.debug(data)
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def check_or_create_folder(self, metadata: ProjectData, folder_path: str) -> str:
        """Check if a given folder exists on sharelatex side.

        Create it recursively if needed and return its id.
        It looks in the metadata and create the missing directories.
        Make sure the metadata are up-to-date when calling this.

        Args:
            metadata (dict): The sharelatex metadata as a structure basis
            folder_path (str): The folder path

        Returns:
            The folder id of the deepest folder created.
        """
        folder_path_as_path = Path(folder_path)
        try:
            folder = lookup_folder(metadata, folder_path)
            return folder["folder_id"]
        except StopIteration:
            logger.debug(f"{folder_path} not found, creation planed")

        parent_id = self.check_or_create_folder(
            metadata, os.path.dirname(folder_path_as_path)
        )
        new_folder = self.create_folder(
            metadata["_id"], parent_id, os.path.basename(folder_path_as_path)
        )
        # This returns the id of the deepest folder
        return typing_cast(str, new_folder["_id"])

    def upload(self, path: str) -> Any:
        """Upload a project (zip) to sharelatex.

        Args:
            path (str): Path to the zip file of a project.

        Returns:
             response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the zip of the upload.
        """
        url = f"{self.base_url}/project/new/upload"
        filename = os.path.basename(path)
        mime = "application/zip"
        files = {"qqfile": (filename, open(path, "rb"), mime)}
        params = {
            "_csrf": self.login_data["_csrf"],
            "qquid": str(uuid.uuid4()),
            "qqfilename": filename,
            "qqtotalfilesize": os.path.getsize(path),
        }
        r = self._post(url, params=params, files=files, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if not response["success"]:
            raise Exception(f"Uploading {path} fails")
        return response

    def share(self, project_id: str, email: str, can_edit: bool = True) -> Any:
        """Send an invitation to share (edit/view) a project.

        Args:
            project_id (str): The project id of the project to share
            email (str): Email of the recipient of the invitation
            can_edit (boolean):True (resp. False) gives read/write (resp. read-only)
            access to the project

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/invite"
        data = {
            "email": email,
            "privileges": "readAndWrite" if can_edit else "readOnly",
            "_csrf": self.login_data["_csrf"],
        }
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def compile(self, project_id: str) -> Any:
        """Trigger a remote compilation.

        Note that this is run against the remote version not the local one.

        Args:
            project_id (str): The project id of the project to compile

        Returns:
            response (dict) status of the request as returned by sharelatex

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/compile"

        data = {"_csrf": self.login_data["_csrf"]}
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        if response["status"] != "success":
            raise CompilationError(response)
        return response

    def update_project_settings(
        self, project_id: str, **settings: Any
    ) -> requests.Response:
        """Update the project settings.

        Update the project settings.

        Args:
            project_id (str): The project id
            settings: the key/value of the settings to change (as keyword arguments)

        Examples:

        .. code:: python

            client.update_project_settings("5f326e4150cb80007f99a7c0",
                                           compiler="xelatex",
                                           name="newname")

        Returns

            The request response.
        """
        url = f"{self.base_url}/project/{project_id}/settings"

        data = {"_csrf": self.login_data["_csrf"]}
        data.update(settings)
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        return r

    def clone(self, project_id: str, project_name: str) -> Any:
        """Copy a project.

        Args:
            project_id (str): The project id of the project to copy
            project_name (str): The project name of the destination project

        Returns:
            response (dict) containing the project_id of the created project

        Raises:
             Exception if something is wrong with the compilation
        """
        url = f"{self.base_url}/project/{project_id}/clone"

        data = {"_csrf": self.login_data["_csrf"], "projectName": project_name}
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def new(self, project_name: str, template: str = "example") -> Any:
        """Create a new example project for the current user.

        Args:
            project_name (str): The project name of the project to create
            template (str): template used for create the new project (default: example)
        """
        url = f"{self.base_url}/project/new"

        data = {
            "_csrf": self.login_data["_csrf"],
            "projectName": project_name,
            "template": template,
        }
        r = self._post(url, data=data, verify=self.verify)
        r.raise_for_status()
        response = r.json()
        return response

    def delete(self, project_id: str, *, forever: bool = False) -> Any:
        """Delete a project for the current user.

        Args:
            project_id (str): The project id of the project to delete
        """
        url = f"{self.base_url}/project/{project_id}"
        data = {"_csrf": self.login_data["_csrf"]}
        params = {"forever": forever}
        r = self._delete(url, data=data, params=params, verify=self.verify)
        r.raise_for_status()
        return r
