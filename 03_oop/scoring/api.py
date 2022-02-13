#!/usr/bin/env python
# -*- coding: utf-8 -*-
from abc import ABC, ABCMeta, abstractmethod

from functools import cached_property

from typing import Any, TypeVar

import json
import datetime
import logging
import hashlib
import uuid
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
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
        self.label = None

    def set_label(self, label: str) -> None:
        self.label = label

    def __get__(self, instance, owner):
        assert self.label, 'not properly configured'
        return instance.__dict__.get(self.label)

    def __set__(self, instance, value):
        assert self.label, 'not properly configured'
        if value:
            value = self.validate_and_clear(value)
        if not value and not self.nullable:
            raise ValidationError(f'can not set nullable value to {instance.__class__.__name__}.{self.label}')
        instance.__dict__[self.label] = value

    @abstractmethod
    def validate_and_clear(self, value: T) -> T:
        return value

    def assert_equal(self, value1, value2, message):
        if value1 != value2:
            raise ValidationError(f'{self.__class__.__name__} {message}')


class CharField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value), str, 'value must be a str')
        return value


class ArgumentsField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value), dict, 'value must be a dict')
        return value


class EmailField(CharField):
    def validate_and_clear(self, value: T) -> T:
        super().validate_and_clear(value)
        self.assert_equal('@' in value, True, 'value must contains "@"')
        return value


class PhoneField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value) in (str, int), True, 'value must be str or int')
        value = str(value)
        self.assert_equal(value.isnumeric(), True, 'value must contains digits only')
        self.assert_equal(len(value), 11, 'value must contains 11 digits')
        self.assert_equal(value[0], '7', 'value must starts with "7"')
        return value


class DateField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value), str, 'value must be a str')
        try:
            return datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError as e:
            raise ValidationError(e) from e


class BirthDayField(DateField):
    def validate_and_clear(self, value: T) -> T:
        dt = super().validate_and_clear(value)
        now = datetime.datetime.now()
        self.assert_equal(
            (now.replace(year=now.year - 70) - dt).days > 0, False, 'value must not to be older then 70 years')
        return dt


class GenderField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value), int, 'value must be an int')
        self.assert_equal(value in GENDERS.keys(), True, 'value must be 0, 1 or 2')
        return value


class ClientIDsField(BaseField):
    def validate_and_clear(self, value: T) -> T:
        self.assert_equal(type(value), list, 'value must be a list')
        self.assert_equal(all(isinstance(val, int) for val in value), True, 'all the values in the list must be ints')
        return value


class RequestMeta(ABCMeta):
    def __init__(cls, name, bases, namespace):
        super().__init__(name, bases, namespace)
        for attr, value in namespace.items():
            if isinstance(value, BaseField):
                value.set_label(attr)


class BaseRequest(metaclass=RequestMeta):
    def __init__(self, **kwargs):
        super().__init__()
        for attr, value in kwargs.items():
            setattr(self, attr, value)
        self.validate()

    def validate(self):
        for attr, field in self.all_fields().items():
            if field.required and getattr(self, attr) is None:
                raise ValidationError(f'attribute {attr} is required in {self.__class__.__name__}')

    def __setattr__(self, key: str, value: Any):
        if not hasattr(self, key):
            raise KeyError(f'no "{key}" attribute in {self.__class__.__name__}')
        super().__setattr__(key, value)

    @classmethod
    def all_fields(cls) -> dict[str, BaseField]:
        return {name: descriptor
                for name, descriptor in cls.__dict__.items()
                if isinstance(descriptor, BaseField)}

    @abstractmethod
    def run(self, request, ctx, store):
        raise NotImplementedError


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def run(self, request, ctx, store):
        ctx['nclients'] = len(self.client_ids)
        return {
            str(client): get_interests(store, client)
            for client in self.client_ids
        }


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

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

    def run(self, request, ctx, store):
        ctx['has'] = [name for name in self.all_fields().keys() if getattr(self, name) is not None]
        if not request['method_request'].is_admin:
            score = get_score(
                store, self.phone, self.phone, self.birthday, self.gender, self.first_name, self.last_name)
        else:
            score = 42

        return {'score': score}


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    _method_request_map = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest,
    }

    @cached_property
    def request_for_method(self) -> BaseRequest:
        try:
            return self._method_request_map[self.method](**self.arguments)
        except KeyError as e:
            raise KeyError(f'no "{self.method}" method registered in MethodRequest map') from e

    def run(self, request, ctx, store):
        return self.request_for_method.run(request, ctx, store)


def check_auth(request: MethodRequest):
    if request.is_admin:
        str_to_hash = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        str_to_hash = request.account + request.login + SALT
    digest = hashlib.sha512(str_to_hash.encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    try:
        method_request = MethodRequest(**request['body'])
        request['method_request'] = method_request

        if not check_auth(method_request):
            return None, FORBIDDEN

        code, response = 200, method_request.run(request, ctx, store)
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
