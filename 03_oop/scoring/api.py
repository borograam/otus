#!/usr/bin/env python
import argparse
import datetime
import hashlib
import json
import logging
import uuid
from abc import ABC
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, TypeVar, Union, Callable

from scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

T = TypeVar('T')


class ValidationError(Exception):
    pass


class BaseField(ABC):
    def __init__(self, required: bool = True, nullable: bool = False) -> None:
        self.required = required
        self.nullable = nullable

    def __set_name__(self, owner, name):
        self.label = name

    def __get__(self, instance, owner):
        return instance.__dict__.get(self.label)

    def __set__(self, instance, value):
        if value is not None:
            value = self.validate_and_clear(value)
        if value is None and not self.nullable:
            raise ValidationError(f'can not set nullable value to {instance.__class__.__name__}.{self.label}')
        instance.__dict__[self.label] = value

    allowed_types = ()

    def validate_and_clear(self, value: T) -> T:
        if not isinstance(value, self.allowed_types):
            self._raise(f'value must be {" or ".join(t.__name__ for t in self.allowed_types)}')
        return value

    def _raise(self, message: str) -> None:
        raise ValidationError(f'{self.__class__.__name__} {message}')


class CharField(BaseField):
    allowed_types = (str,)


class ArgumentsField(BaseField):
    allowed_types = (dict,)


class EmailField(CharField):
    def validate_and_clear(self, value: str) -> str:
        value = super().validate_and_clear(value)
        if '@' not in value:
            self._raise('value must contains "@"')
        return value


class PhoneField(BaseField):
    allowed_types = (str, int)

    def validate_and_clear(self, value: Union[str, int]) -> str:
        value: str = str(super().validate_and_clear(value))
        if not value.isnumeric():
            self._raise('value must contains digits only')
        if len(value) != 11:
            self._raise('value must contains 11 digits')
        if value[0] != '7':
            self._raise('value must starts with "7"')
        return value


class DateField(BaseField):
    allowed_types = (str,)

    def validate_and_clear(self, value: str) -> datetime.datetime:
        value = super().validate_and_clear(value)
        try:
            return datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError as e:
            raise ValidationError(e) from e


class BirthDayField(DateField):
    def validate_and_clear(self, value: str) -> datetime.datetime:
        dt = super().validate_and_clear(value)
        now = datetime.datetime.now()
        if (now.replace(year=now.year - 70) - dt).days > 0:
            self._raise('value must not to be older then 70 years')
        return dt


class GenderField(BaseField):
    allowed_types = (int,)

    def validate_and_clear(self, value: int) -> int:
        value = super().validate_and_clear(value)
        if value not in GENDERS.keys():
            self._raise('value must be 0, 1 or 2')
        return value


class ClientIDsField(BaseField):
    allowed_types = (list,)

    def validate_and_clear(self, value: list[int]) -> list[int]:
        value = super().validate_and_clear(value)
        if not all(isinstance(val, int) for val in value):
            self._raise('all the values in the list must be ints')
        if not value:
            self._raise('empty list')
        return value


class BaseRequest(ABC):
    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._validated = False

    def validate(self):
        for attr, value in self._kwargs.items():
            setattr(self, attr, value)  # тут происходит валидация полей

        for attr, field in self.all_fields().items():
            if field.required and getattr(self, attr) is None:
                raise ValidationError(f'attribute {attr} is required in {self.__class__.__name__}')
        self._validated = True

    def __setattr__(self, key: str, value: Any):
        if not hasattr(self, key) and not key.startswith('_'):
            raise KeyError(f'no "{key}" attribute in {self.__class__.__name__}')
        super().__setattr__(key, value)

    @classmethod
    def all_fields(cls) -> dict[str, BaseField]:
        return {name: descriptor
                for name, descriptor in cls.__dict__.items()
                if isinstance(descriptor, BaseField)}


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False)
    last_name = CharField(required=False)
    email = EmailField(required=False)
    phone = PhoneField(required=False)
    birthday = BirthDayField(required=False)
    gender = GenderField(required=False)

    _must_exist_the_same_time = (
        ('phone', 'email'),
        ('first_name', 'last_name'),
        ('gender', 'birthday'),
    )

    def validate(self):
        super().validate()

        if not any(
                all(
                    getattr(self, f) is not None
                    for f in fields
                )
                for fields in self._must_exist_the_same_time
        ):
            raise ValidationError(f"{' or '.join(','.join(fields) for fields in self._must_exist_the_same_time)} "
                                  f"must be filled at th same time")


class MethodRequest(BaseRequest):
    account = CharField(required=False)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class Runner:
    handlers: dict[type, Callable] = {}

    @classmethod
    def register(cls, request_type: type) -> Callable[[Callable], Callable]:
        def deco(func: Callable) -> Callable:
            if request_type in cls.handlers:
                raise KeyError(f'{request_type} already registered in Runner before!')
            cls.handlers[request_type] = func
            return func

        return deco

    def __init__(self, request: BaseRequest):
        self.request = request

    def run(self, http_request: dict, ctx: dict, store: Any):
        request_class = self.request.__class__
        if request_class not in self.handlers:
            raise KeyError(f'{request_class.__name__} did not registered in Runner')
        return self.handlers[request_class](self.request, http_request, ctx, store)


@Runner.register(MethodRequest)
def method_request_runner(request: MethodRequest, http_request: dict, ctx: dict, store: Any):
    method_request_map = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest,
    }
    try:
        inner_request: BaseRequest = method_request_map[request.method](**request.arguments)
    except KeyError as e:
        raise KeyError(f'no "{request.method}" method registered in method_request_runner map') from e

    inner_request.validate()

    return Runner(inner_request).run(http_request, ctx, store)


@Runner.register(OnlineScoreRequest)
def online_score_request_runner(request: OnlineScoreRequest, http_request: dict, ctx: dict, store: Any):
    ctx['has'] = [name for name in request.all_fields().keys() if getattr(request, name) is not None]
    if not http_request['method_request'].is_admin:
        score = get_score(
            store, request.phone, request.phone, request.birthday, request.gender, request.first_name,
            request.last_name)
    else:
        score = 42

    return {'score': score}


@Runner.register(ClientsInterestsRequest)
def clients_interests_request_runner(request: ClientsInterestsRequest, http_request: dict, ctx: dict, store: Any):
    ctx['nclients'] = len(request.client_ids)
    return {
        str(client): get_interests(store, client)
        for client in request.client_ids
    }


def check_auth(request: MethodRequest):
    if request.is_admin:
        str_to_hash = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        str_to_hash = request.account + request.login + SALT
    digest = hashlib.sha512(str_to_hash.encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request: dict, ctx: dict, store: Any):
    response, code = None, None
    try:
        method_request = MethodRequest(**request['body'])
        request['method_request'] = method_request

        method_request.validate()

        if not check_auth(method_request):
            return None, FORBIDDEN

        code, response = 200, Runner(method_request).run(request, ctx, store)
    except ValidationError as e:
        return str(e), INVALID_REQUEST
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s", self.path, data_string, context["request_id"])
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s", e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=8080)
    ap.add_argument("-l", "--log")
    args = ap.parse_args()

    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
