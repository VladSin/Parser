# Parser PE
## Parser формата PE (Portable Executable), позволяющий извлекать данные из заголовка PE файла, а также внедрять собственные библиотеки.

### В результате Parser выполняет:
* Извлечение определенных данных из заголовка PE файла 
* Извлечение списка секций и импортируемых библиотек
* Формирование json-файла с полученными данными 
* Добавление дополнительных библиотеки в таблицу импорта файла

### Parser.exe принимает три параметра:
* Ключ ‘-al’ при необходимости добавления библиотеки
* Путь к целевому PE файлу, который необходимо изменить
* Имя библиотеки, которую необходимо добавить
