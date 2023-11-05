# icmp

Требования

Для начала о задаче, которая стояла:  разработать систему для мониторинга состояния сетевых
устройств (например, роутеров или свитчей).

Функциональные Требования:
• Перед началом мониторинга, система должна подключиться к каждому устройству и настроить его так, чтобы устройство стало доступным для ICMP пинга.
• Система должна опрашивать состояние устройств через ICMP (ping).
• Результаты опроса должны записываться в лог-файл, содержащий информацию о времени опроса, IP-адресе устройства и результате опроса.
• В случае, если устройство не отвечает более N раз, система должна отправлять уведомления администратору на почтовый ящик.
• На вход системе подается YAML файл, содержащий:
• Список устройств и данные для их подключения.
• Путь к файлу для логирования.
• Почтовый ящик для отправки уведомлений.
• Количество неудачных попыток подключения, после которых следует отправить уведомление.

Requirements:
- Python 3.9+
- Paramiko
- PyYAML

  
Теперь о самом коде:

файл MAIN.PY:

Этот Python-скрипт предназначен для мониторинга сетевых устройств. Он включает в себя классы и функции для конфигурации устройств, проверки их доступности с помощью ICMP пингов, логирования событий, отправки уведомлений по электронной почте в случае недоступности устройства, и чтения конфигурационных данных из YAML-файла. Вот основные компоненты кода:

Класс Device:
Представляет сетевое устройство с IP-адресом, именем пользователя и паролем.
Имеет метод configure_device для настройки устройства через SSH и его подготовки к ответам на ICMP-запросы.

Класс DeviceManager:
Управляет группой устройств (Device объектов).
Проверяет доступность каждого устройства с помощью ICMP пингов.
Если устройство не отвечает определенное количество раз (max_failures), использует NotificationManager для отправки уведомления.

Класс ICMPMonitor:
Отвечает за мониторинг доступности отдельного устройства с помощью ICMP пинга.

Класс NotificationManager:
Управляет процессом отправки уведомлений по электронной почте, если устройство недоступно.

Класс Logger:
Логирует различные уровни сообщений (информация, предупреждения, ошибки) в файл лога.

Класс MailSender:
Отправляет электронные письма через SMTP сервер.

Класс ConfigLoader:
Загружает конфигурационные данные из YAML файла.

Функция main:
Точка входа скрипта.
Загружает конфигурацию, инициализирует логгер и создает объекты для устройств и менеджера уведомлений.
Выполняет циклическую проверку доступности устройств и конфигурацию устройств в начале.
В процессе работы скрипта, если устройство не отвечает на пинг определенное количество раз (указанное в конфигурации), система отправит уведомление. 

Код включает обработку исключений для обработки ошибок подключения SSH, аутентификации, ошибок ICMP и других неожиданных ситуаций. Сообщения об этих событиях логируются и записываются в лог-файл.


ФАЙЛ CONFIG.YAML

Данный файл содержит настройки для логирования, уведомлений по электронной почте и параметры для устройств, которые необходимо отслеживать. 
log_path: Путь к директории, где будут сохраняться лог-файлы скрипта.
max_failures: Максимальное количество раз, когда устройство может не ответить на пинг перед тем, как будет отправлено уведомление о его недоступности.
monitoring_interval: Интервал времени в секундах, через который скрипт будет повторять проверку доступности устройств.
smtp_server: Адрес SMTP-сервера, который будет использоваться для отправки уведомлений по электронной почте.
smtp_port: Порт SMTP-сервера для отправки электронной почты.
sender_email: Адрес электронной почты отправителя, с которого будут отправляться уведомления.
sender_password: Пароль от электронной почты отправителя, используемый для аутентификации на SMTP-сервере.
recipient_email: Адрес электронной почты получателя, на который будут приходить уведомления о недоступности устройств.
devices: Список устройств, которые необходимо мониторить. Для каждого устройства указывается:
ip: IP-адрес устройства в сети.
username: Имя пользователя для доступа к устройству.
password: Пароль для доступа к устройству.

Файл с именем вроде paramiko.log содержит журнал (лог) работы библиотеки Paramiko, которая используется для выполнения SSH операций.

В файл monitoring.log (или подобном, имя которого будет сформировано с учетом текущей даты и времени) записываются сообщения логгера, связанные с процессом мониторинга устройств в сети.



Стоит также отметить как проводилось тетстирование данного скрипта в реальных условиях. 
Для имитации сети был выбран эмулятор gns3. Он выбран несулчайно, так как именно он поддерживает связь локальных физических сетей и виртуальных сетей эмулятора. Отдельно стоит отметить как была настроена связь gns и пк. В пк был создан loopback интерфейс, с адресом 192.168.73.1, который был замкнут сам на себя. В gns был выбран образ cloud, имитирующий нашу сеть и соединенный кабелем через интерфейс ethernet2 (созданный loopback) с коммутатором. Таким образом, нашо облако имело адрес 192.168.73.1 в локальной физический сети (через ipconfig были проверены корректные настройки), а также, облако имело аналогичный адрес в виртулаьной сети gns. Комутатору был присвоен соотвествующий адресс 192.168.73.2, к которому в последсвтие и будет все подключение производиться. На коммутаторе было настроено подключение по ssh, с логином и паролем из yaml-файла. Так как, подключение из скрипта по ssh к данному коммутатору доставило много проблем, было принято решение, помимо лог файла, который нужен по заданию, добавить лог-файл paramiko.log для отслеживания событий касательно подключения по ssh. Далее, в случае успешного подключения по ssh, устройство настраивалось для возможности принятия icmp-пинга. Для использование списка комманд на устройстве был применен метод invoke_shell().
Без использования invoke_shell(), мы не сможем установить интерактивную сессию с устройством. Это означает, что мы не сможем отправлять последовательности команд, которые требуют подтверждения или дополнительных вводов после выполнения каждой команды. В нашем случае, для настройки устройства требуется отправить серию команд в конфигурационном режиме, что возможно только в рамках интерактивной сессии. Без invoke_shell(), мы могли бы использовать метод exec_command() для выполнения отдельных команд без интерактивности, но это не подходит для сценариев, где нужно выполнить несколько команд в определенной последовательности в рамках одной сессии (например, вход в конфигурационный режим, изменение настроек и выход из конфигурационного режима, как происходит у нас в скрипте).

Далее производился пинг, в случае если пинг проходил 3 раза, программа с соовтествующим сообщением заврешается, результат записывается в лог-файл monitoring.log. В случае если пинг не проходил, программа пытается произвести пинг количесство раз, указанное в yaml-файле, а даллее, по истечению этого количесства раз, на указаную почту отправялось следующее письмо: 

Тема: Network Device Monitoring Alert
от: yaroslavkuzmin11@gmail.com
Кому: Yaroslav_Kuzmin2002@mail.ru
Текст письма: Device 192.168.73.2 is not accessible!

Все части кода выполняются до того момента, пока устрйоства в списке не закончатся.
В програамме также присутсвуют множество обработчиков ошибок, в случае неправильных дейтсвий, которую помогут понять нам в чем проблема.

В файле monitoring.log сначала представлены логи в случае корректного icmp-пинга на устройство 192.168.73.2, которые мы настаривали. Далее логи пинга к устройству 192.168.73.3, котрого нет в нашей сети, и внесено в список для проверки корректности обработки всех случаев.

Вся основная реализация написана в одном файле так как код имеет небольшой объем, однако, в случае расширения функционала, рекомендуется разбить классы по файлам, для удобства работы с ними. 



Для создания избыточной и расширяемой архитектуры мониторинга устройств в сети, можно внести ряд улучшений и изменений в текущую структуру. 

Реализация нескольких экземпляров сервиса мониторинга, работающих параллельно, может обеспечить высокую доступность и балансировку нагрузки.
Развертывание агентов мониторинга на устройствах или в различных сетевых сегментах для сбора данных и отправки их на центральный сервер.
Расширение функционала оповещений путем интеграции с платформами на подобие Slack, Microsoft Teams, и т.д.
Внедрение различных уровней тревог и фильтрацию оповещений на основе важности и типа события.
Реализация функционала для автоматического выполнения скриптов или команд в ответ на определенные события (например, перезапуск сервисов или маршрутизаторов).
Контейнеризация сервиса мониторинга для упрощения развертывания и масштабирования (например, использование Docker).
Внедрение многофакторной аутентификации для доступа к системе мониторинга.
Использование VPN или шифрования для безопасного соединения с устройствами в сети.


Данные улучшения могут быть реализованы, но на это потребуется больше времени.











