import inspect
import os
import time
import typing

from locust import User, events, task

# inspired from https://github.com/gtato/sharelatex-loadgenerator
from sharelatex import GitlabAuthenticator, SyncClient

BASE_URL = typing.cast(str, os.environ.get("CI_BASE_URL"))
USERNAME = typing.cast(str, os.environ.get("CI_USERNAME"))
PASSWORD = typing.cast(str, os.environ.get("CI_PASSWORD"))
AUTH_TYPE = typing.cast(str, os.environ.get("CI_AUTH_TYPE"))


class LocustClient(SyncClient):
    def __init__(self) -> None:
        authenticator = GitlabAuthenticator()
        authenticator.authenticate(
            base_url=BASE_URL, username=USERNAME, password=PASSWORD, verify=False
        )
        super().__init__(
            base_url=BASE_URL,
            username=USERNAME,
            password=PASSWORD,
            verify=False,
            authenticator=authenticator,
        )

    def __getattribute__(self, name: str) -> typing.Any:
        """Override client methods

        From
        https://docs.locust.io/en/stable/testing-other-systems.html#sample-xml-rpc-locust-client

        The idea is to reuse an existing client (here python-sharelatex) and use
        it in locust The only thing we should pay attention at is to send right
        statistics to locust.  So the effect of this method is to make sure to
        fire the event before and after to funtion calls of the sharelatex
        client More specificaly it decorates at run time the functions of the
        client class.  !from python with love!
        """
        attr = super().__getattribute__(name)
        if inspect.ismethod(attr):

            def _wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
                start_time = time.time()
                result = None
                try:
                    result = attr(*args, **kwargs)
                except Exception as e:
                    total_time = int((time.time() - start_time) * 1000)
                    events.request_failure.fire(
                        request_type="syncclient",
                        name=name,
                        response_time=total_time,
                        exception=e,
                    )
                finally:
                    total_time = int((time.time() - start_time) * 1000)
                    events.request_success.fire(
                        request_type="syncclient",
                        name=name,
                        response_time=total_time,
                        response_length=0,
                    )
                return result

            return _wrapper
        else:
            return attr


class WebsiteUser(User):
    min_wait = 5000
    max_wait = 10000

    def __init__(self, environment: typing.Any) -> None:
        super().__init__(environment)
        try:
            self.client = LocustClient()
        except Exception as e:
            events.request_failure.fire(
                request_type="syncclient", name="new", response_time=0, exception=e
            )

    @task(1)
    def compile(self) -> None:
        project = self.client.new("from_locust")
        try:
            self.client.compile(project["project_id"])
        except Exception as e:
            raise e
        finally:
            self.client.delete(project["project_id"], forever=True)
