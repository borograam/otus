#log_analyzer

##Установка
Я долго думал, надо ли закладывать на каждое задание свой собственный virtualenv, решил в итоге, что будет один общий.

Да, в рамках этого задания не было использования внешних библиотек, так что, можно запускать и системым python3. Через pipenv подтянется 3.10

```shell
pipenv install
```
##Запуск тестов
```shell
pipenv run python -m unittest tests.py -v
```

##Запуск программы
```shell
pipenv run ./log_analyzer.py
```
Существование конфиг-файла (пусть и пустого) - обязательно. По-умолчанию программа смотрит в существующий рядом `./config.ini`. Можно уточнить другой через опцию `--config`.

###Logging
При необходимости писать лог в файл, необходимо раскоментировать опцию конфига `log_filename` и указать необходимый путь