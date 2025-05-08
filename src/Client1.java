import java.io.*;          
import java.net.*;          
import java.util.Scanner;   
import java.util.concurrent.CountDownLatch; 
import java.util.List;    
import java.util.ArrayList; 
import java.util.Arrays;   
import java.util.Collections; 
import java.util.HashMap;  
import java.util.Map;       

public class Client1 {

    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;

    private static final byte DHCP_DISCOVER = 5;
    private static final byte DHCP_OFFER = 6;
    private static final byte DHCP_REQUEST = 7;
    private static final byte DHCP_ACK = 8;
    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10;


    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;
    private static final byte ARP_RESPONSE = 23;

    private static final byte DNS_DISCOVER = 30;
    private static final byte DNS_ANNOUNCE = 31;
    private static final byte DNS_REGISTER = 32;
    private static final byte DNS_RESOLVE = 33;
    private static final byte DNS_RESPONSE = 34;

    private static final byte HTTP_GET = 40;         // Код для запроса HTML-страницы
    private static final byte HTTP_RESPONSE = 41;    // Код для ответа с HTML-страницей

    private static String CLIENT_MAC;                // MAC-адрес клиента
    private static String CLIENT_IP = "0.0.0.0";     // IP-адрес клиента (изначально нет IP)
    private static boolean ipAssigned = false;       // Флаг успешного получения IP

    private static String ROUTER_ADDRESS;            // IP-адрес маршрутизатора
    private static int ROUTER_PORT;                  // Порт маршрутизатора
    private static final String ROUTER_MAC = "AA:BB:CC:DD:EE:FF"; // MAC-адрес маршрутизатора


    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;


    private volatile String dhcpOfferedIP = null;    // IP, предложенный через DHCP
    private volatile List<String> availableIPs = new ArrayList<>(); // Список доступных IP
    private volatile boolean dhcpAckReceived = false;// Флаг получения DHCP ACK
    private volatile CountDownLatch dhcpLatch = new CountDownLatch(1); // Синхронизатор для DHCP

    // ARP
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());
    private volatile String arpResponseMAC = null;   // MAC в ответ на ARP-запрос


    private DNSClient dnsClient;                     // Клиент DNS для разрешения имен

    // Информация о клиенте
    private int clientNumber;                        // Номер клиента для идентификации
    private boolean manualIPSelection;               // Флаг для ручного выбора IP
    private String htmlPage;                         // Содержимое HTML-страницы клиента

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        int clientNumber = 1;

        System.out.println("Введите MAC адрес клиента (или нажмите Enter для AA:BB:CC:DD:EE:0" + clientNumber + "):");
        CLIENT_MAC = scanner.nextLine();
        if (CLIENT_MAC.isEmpty()) {
            CLIENT_MAC = "AA:BB:CC:DD:EE:0" + clientNumber;
        }

        // Запрашиваем адрес
        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для 127.0.0.1):");
        ROUTER_ADDRESS = scanner.nextLine();
        if (ROUTER_ADDRESS.isEmpty()) {
            ROUTER_ADDRESS = "127.0.0.1";
        }

        // Запрашиваем порт
        System.out.println("Введите порт маршрутизатора (или нажмите Enter для 8081):");
        String portInput = scanner.nextLine();
        ROUTER_PORT = portInput.isEmpty() ? 8081 : Integer.parseInt(portInput);


        System.out.println("Хотите вручную выбрать IP-адрес? (true/false):");
        boolean manualIPSelection = Boolean.parseBoolean(scanner.nextLine());


        Client1 client = new Client1();
        client.clientNumber = clientNumber;  // Устанавливаем номер клиента
        client.manualIPSelection = manualIPSelection;  // Устанавливаем флаг ручного выбора IP
        client.start(scanner);
    }

    public void start(Scanner scanner) {
        try {
            socket = new Socket(ROUTER_ADDRESS, ROUTER_PORT);  // Создаем сокет с указанным адресом и портом
            outputStream = socket.getOutputStream();  // Получаем поток для отправки данных
            inputStream = socket.getInputStream();  // для приема данных
            System.out.println("Клиент " + clientNumber + " подключился к " + ROUTER_ADDRESS + ":" + ROUTER_PORT);

            // Запускаем поток для прослушивания входящих сообщений
            Thread listenThread = new Thread(this::listenForMessages);  // Создаем новый поток с методом прослушивания
            listenThread.setDaemon(true);  // Устанавливаем как демон (завершится при завершении основного потока)
            listenThread.start();  // Запускаем поток

            // Запускаем процесс получения IP через DHCP
            Thread.sleep(1000);
            performDhcpProcess(scanner);

            // Проверяем, успешно ли получен IP-адрес
            if (!ipAssigned) {
                System.out.println("Не удалось получить IP-адрес через DHCP");
                socket.close();
                return;
            }

            System.out.println("IP-адрес " + CLIENT_IP + " успешно получен через DHCP");

            // Инициализируем DNS-клиент для работы с доменными именами
            dnsClient = new DNSClient(CLIENT_MAC, CLIENT_IP, this::sendMessage);  // Создаем DNS-клиент
            System.out.println("DNS-клиент инициализирован");

            // Создаем HTML-страницу для этого клиента
            initializeHtmlPage();  // Инициализируем HTML-страницу

            // меню
            while (true) {
                System.out.println("\nМеню клиента " + clientNumber + ":");
                System.out.println("1. Показать информацию о клиенте");
                System.out.println("2. Обновить IP-адрес (новый DHCP запрос)");
                System.out.println("3. Отправить сообщение другому клиенту");
                System.out.println("4. Показать ARP таблицу");
                System.out.println("5. Управление DNS");
                System.out.println("6. Получить HTML-страницу по доменному имени");
                System.out.println("7. Выход");
                System.out.print("Выберите действие: ");

                String choice = scanner.nextLine();

                // Обрабатываем выбор пользователя
                if (choice.equals("1")) {
                    // Показываем информацию о клиенте
                    System.out.println("Информация о клиенте:");
                    System.out.println("Номер клиента: " + clientNumber);
                    System.out.println("MAC-адрес: " + CLIENT_MAC);
                    System.out.println("IP-адрес: " + CLIENT_IP);
                    System.out.println("Статус: " + (ipAssigned ? "IP назначен" : "IP не назначен"));
                }
                else if (choice.equals("2")) {
                    // Перезапускаем процесс DHCP для обновления IP-адреса
                    System.out.println("Запуск нового DHCP запроса...");
                    // Сбрасываем состояние DHCP
                    dhcpOfferedIP = null;  // Сбрасываем предложенный IP
                    availableIPs.clear();  // Очищаем список доступных IP
                    dhcpAckReceived = false;  // Сбрасываем флаг подтверждения
                    ipAssigned = false;  // Сбрасываем флаг назначения IP
                    CLIENT_IP = "0.0.0.0";  // Сбрасываем текущий IP
                    dhcpLatch = new CountDownLatch(1);  // Создаем новый синхронизатор

                    // Запускаем процесс получения IP
                    performDhcpProcess(scanner);
                }
                else if (choice.equals("3")) {
                    if (!ipAssigned) {  // Проверяем, есть ли у нас IP-адрес
                        System.out.println("Сначала необходимо получить IP-адрес");
                        continue;
                    }

                    // Запрашиваем адрес назначения
                    System.out.println("Введите IP адрес или доменное имя назначения:");
                    String destination = scanner.nextLine();
                    String destinationIP = destination;

                    // Проверяем, является ли это доменным именем
                    if (!destination.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {  // Если не соответствует формату IP
                        // Пытаемся разрешить доменное имя в IP
                        destinationIP = dnsClient.resolveDomain(destination);
                        if (destinationIP == null) {  // Если не удалось разрешить имя
                            System.out.println("Не удалось разрешить доменное имя: " + destination);
                            continue;  // Возвращаемся к началу цикла
                        }
                        System.out.println("Доменное имя " + destination + " разрешено в IP: " + destinationIP);
                    }

                    System.out.print("Введите сообщение: ");
                    String data = scanner.nextLine();

                    // Получаем MAC адрес через ARP запрос, если нужно
                    String destinationMAC = getMacAddress(destinationIP);  // Получаем MAC по IP
                    if (destinationMAC == null) {  // Если не удалось получить MAC
                        System.out.println("ARP не удался. Не получилось узнать MAC для IP: " + destinationIP);
                        continue;  // Возвращаемся к началу цикла
                    }

                    sendMessage(destinationMAC, CLIENT_MAC, PING, destinationIP, CLIENT_IP, data);
                    System.out.println("Сообщение отправлено");
                }
                else if (choice.equals("4")) {
                    // Показываем ARP таблицу
                    System.out.println("ARP таблица:");
                    if (tableARP.isEmpty()) {  // Если таблица пуста
                        System.out.println("Таблица пуста");
                    } else {
                        // Выводим все записи в таблице
                        for (Map.Entry<String, String> entry : tableARP.entrySet()) {
                            System.out.println("IP: " + entry.getKey() + " -> MAC: " + entry.getValue());
                        }
                    }
                }
                else if (choice.equals("5")) {
                    // Вызываем меню управления DNS
                    showDnsMenu(scanner);
                }
                else if (choice.equals("6")) {
                    // Запрашиваем HTML-страницу по доменному имени или IP
                    System.out.print("Введите доменное имя или IP-адрес: ");
                    String domain = scanner.nextLine();  // Считываем ввод пользователя
                    getHtmlPage(domain);  // Получаем HTML-страницу
                }
                else if (choice.equals("7")) {
                    // Выход из программы
                    System.out.println("Завершение работы клиента " + clientNumber);
                    socket.close();
                    break;
                }
                else {
                    System.out.println("Неверный выбор, попробуйте снова");
                }
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Инициализирует HTML-страницу клиента с текущей информацией.
     */
    private void initializeHtmlPage() {
        // Создаем простую HTML-страницу с информацией о клиенте
        htmlPage = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>Клиент " + clientNumber + "</title>\n" +
                "    <style>\n" +
                "        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }\n" +
                "        h1 { color: #4285f4; }\n" +
                "        .info { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }\n" +
                "        .subtitle { color: #666; }\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <h1>Информационная страница клиента " + clientNumber + "</h1>\n" +
                "    <div class=\"info\">\n" +
                "        <h2>Сетевая информация:</h2>\n" +
                "        <p><strong>MAC-адрес:</strong> " + CLIENT_MAC + "</p>\n" +
                "        <p><strong>IP-адрес:</strong> " + CLIENT_IP + "</p>\n" +
                "        <p class=\"subtitle\">Страница сгенерирована: " + new java.util.Date() + "</p>\n" +
                "    </div>\n" +
                "</body>\n" +
                "</html>";
    }

    /*
     * Отображает и обрабатывает меню DNS-клиента.
     * Позволяет искать DNS-серверы, выбирать их, регистрировать и разрешать доменные имена.

     */
    private void showDnsMenu(Scanner scanner) {
        // Проверяем, есть ли у нас IP-адрес
        if (!ipAssigned) {
            System.out.println("Сначала необходимо получить IP-адрес");
            return;  // Выходим из метода
        }

        while (true) {
            System.out.println("\nМеню DNS:");
            System.out.println("1. Поиск DNS-серверов");
            System.out.println("2. Выбрать DNS-сервер");
            System.out.println("3. Зарегистрировать доменное имя");
            System.out.println("4. Найти IP по доменному имени");
            System.out.println("5. Показать кэш DNS");
            System.out.println("6. Вернуться в главное меню");
            System.out.print("Выберите действие: ");

            String choice = scanner.nextLine();

            // Обрабатываем выбор пользователя
            if (choice.equals("1")) {
                dnsClient.discoverDnsServers();
            }
            else if (choice.equals("2")) {
                // Выбираем DNS-сервер из списка найденных
                Map<String, String> servers = dnsClient.getDnsServers();  // Получаем список серверов
                if (servers.isEmpty()) {  // Если список пуст
                    System.out.println("Нет доступных DNS-серверов. Выполните поиск сначала.");
                    continue;
                }

                // Выводим список доступных серверов
                System.out.println("Доступные DNS-серверы:");
                int i = 1;
                String[] serverIPs = new String[servers.size()];  // Массив для хранения IP-адресов
                for (String ip : servers.keySet()) {
                    System.out.println(i + ". " + ip + " (" + servers.get(ip) + ")");
                    serverIPs[i-1] = ip;  // Сохраняем IP в массив
                    i++;
                }

                // Запрашиваем выбор пользователя
                System.out.print("Выберите номер сервера: ");
                try {
                    int serverIdx = Integer.parseInt(scanner.nextLine());  // Считываем и преобразуем ввод
                    if (serverIdx >= 1 && serverIdx <= serverIPs.length) {  // Проверяем валидность выбора
                        dnsClient.selectDnsServer(serverIPs[serverIdx-1]);  // Выбираем сервер
                    } else {
                        System.out.println("Неверный номер");
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Пожалуйста, введите число");
                }
            }
            else if (choice.equals("3")) {
                // Регистрируем доменное имя
                System.out.print("Введите доменное имя: ");
                String domain = scanner.nextLine();  // Считываем имя домена

                // Запрашиваем IP для домена или используем наш IP
                System.out.print("Введите IP-адрес (или нажмите Enter для " + CLIENT_IP + "): ");
                String ip = scanner.nextLine();  // Считываем IP
                if (ip.isEmpty()) {  // Если IP не указан
                    ip = CLIENT_IP;  // Используем наш IP
                }

                // Регистрируем домен
                dnsClient.registerDomain(domain, ip);
            }
            else if (choice.equals("4")) {
                // Разрешаем доменное имя в IP
                System.out.print("Введите доменное имя: ");
                String domain = scanner.nextLine();  // Считываем имя домена

                // Разрешаем имя и выводим результат
                String ip = dnsClient.resolveDomain(domain);
                if (ip != null) {  // Если удалось разрешить
                    System.out.println("IP-адрес для " + domain + ": " + ip);
                } else {
                    System.out.println("Не удалось разрешить домен " + domain);
                }
            }
            else if (choice.equals("5")) {
                // Показываем кэш DNS (сохраненные соответствия домен-IP)
                Map<String, String> cache = dnsClient.getDnsCache();  // Получаем кэш
                if (cache.isEmpty()) {  // Если кэш пуст
                    System.out.println("DNS-кэш пуст");
                } else {
                    // Выводим все записи в кэше
                    System.out.println("DNS-кэш:");
                    int i = 1;
                    for (Map.Entry<String, String> entry : cache.entrySet()) {
                        System.out.println(i++ + ". " + entry.getKey() + " -> " + entry.getValue());
                    }
                }
            }
            else if (choice.equals("6")) {
                return;  // Возврат в главное меню
            }
            else {
                System.out.println("Неверный выбор, попробуйте снова");
            }
        }
    }

    /**
     * Выполняет процесс DHCP для получения IP-адреса от сервера.
     */
    private void performDhcpProcess(Scanner scanner) {
        try {
            // Отправляем DHCP Discover для обнаружения DHCP-сервера
            System.out.println("Отправка DHCP Discover...");
            // Широковещательный запрос (FF:FF:FF:FF:FF:FF) для поиска DHCP-сервера
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_DISCOVER, "255.255.255.255", "0.0.0.0", "");

            Thread.sleep(3000);  // Ждем 3 секунды

            // Выбираем IP-адрес из предложенных
            String requestedIP = null;  // IP, который мы хотим запросить

            if (dhcpOfferedIP != null) {
                // Если получили предложение IP через DHCP Offer, используем его
                requestedIP = dhcpOfferedIP;
                System.out.println("Используем предложенный IP: " + requestedIP);
            } else if (!availableIPs.isEmpty()) {
                // Если получили список доступных IP, но не получили DHCP Offer
                if (manualIPSelection) {
                    // Если выбран режим ручного выбора IP, показываем доступные IP
                    System.out.println("\nДоступные IP-адреса:");
                    for (int i = 0; i < availableIPs.size(); i++) {
                        System.out.println((i + 1) + ". " + availableIPs.get(i));
                    }

                    // Запрашиваем выбор пользователя
                    int choice = -1;
                    while (choice < 1 || choice > availableIPs.size()) {  // Пока не будет валидный выбор
                        System.out.print("Выберите IP (1-" + availableIPs.size() + "): ");
                        try {
                            choice = Integer.parseInt(scanner.nextLine());  // Считываем и преобразуем ввод
                        } catch (NumberFormatException e) {
                            System.out.println("Пожалуйста, введите число");
                        }
                    }

                    // Используем выбранный IP
                    requestedIP = availableIPs.get(choice - 1);
                    System.out.println("Выбран IP: " + requestedIP);
                } else {
                    // выбираем первый доступный IP
                    requestedIP = availableIPs.get(0);
                    System.out.println("Автоматически выбран первый доступный IP: " + requestedIP);
                }
            } else {
                // Если не получили ни DHCP Offer, ни список доступных IP
                System.out.println("Не получен ни DHCP Offer, ни список доступных IP, процесс не завершен");
                return;  // Выходим из метода
            }

            // Отправляем DHCP Request для запроса конкретного IP
            System.out.println("Отправка DHCP Request для IP: " + requestedIP);
            // Широковещательный запрос с указанием желаемого IP
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_REQUEST, "255.255.255.255", "0.0.0.0", requestedIP);

            Thread.sleep(3000);

            // Проверяем результат процесса
            if (dhcpAckReceived) {  // Если получили подтверждение
                // Устанавливаем полученный IP
                CLIENT_IP = requestedIP;
                ipAssigned = true;  // Устанавливаем флаг успешного получения IP
                System.out.println("DHCP процесс завершен успешно, получен IP: " + CLIENT_IP);
                // Инициализируем HTML-страницу с новым IP
                initializeHtmlPage();
            } else {
                System.out.println("Не получен DHCP ACK, процесс не завершен");
            }

        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Получает MAC-адрес по IP-адресу.
     * Сначала проверяет в локальной ARP-таблице, если там нет - отправляет ARP-запрос.
     */
    private String getMacAddress(String ip) {
        // Проверяем, есть ли IP в нашей ARP-таблице
        if (tableARP.containsKey(ip)) {
            return tableARP.get(ip);  // Возвращаем MAC из таблицы
        } else {
            // Если IP нет в таблице, отправляем ARP-запрос
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, ARP_REQUEST, ip, CLIENT_IP, "");

            // Ждем, пока придёт ARP-ответ
            try {
                int tries = 0;  // Счетчик попыток
                while (arpResponseMAC == null && tries < 10) {  // Пока нет ответа и не превышен лимит попыток
                    Thread.sleep(200);  // Ждем 200 мс
                    tries++;
                }
                if (arpResponseMAC != null) {  // Если получили ответ
                    String mac = arpResponseMAC;  // Сохраняем полученный MAC
                    arpResponseMAC = null;  // Сбрасываем для следующего запроса
                    tableARP.put(ip, mac);  // Добавляем в ARP-таблицу
                    return mac;  // Возвращаем MAC
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private static int byteArrayToInt(byte[] bytes) {
        // Преобразуем 4 байта в int, учитывая старшинство байтов (big-endian)
        return ((bytes[0] & 0xFF) << 24) |  // Первый байт (старший)
                ((bytes[1] & 0xFF) << 16) |  // Второй байт
                ((bytes[2] & 0xFF) << 8) |   // Третий байт
                (bytes[3] & 0xFF);           // Четвертый байт (младший)
    }

    private static byte[] intToByteArray(int value) {
        // Преобразуем int в 4 байта, учитывая старшинство байтов (big-endian)
        return new byte[] {
                (byte)(value >>> 24),  // Первый байт (старший)
                (byte)(value >>> 16),  // Второй байт
                (byte)(value >>> 8),   // Третий байт
                (byte)value            // Четвертый байт (младший)
        };
    }

    /**
     * Прослушивает входящие сообщения от маршрутизатора.
     * Запускается в отдельном потоке и работает до закрытия сокета.
     */
    private void listenForMessages() {
        try {
            while (true) {
                // Читаем MAC-адрес назначения (17 байт)
                byte[] destMacBuffer = new byte[MAC_SIZE];
                int bytesRead = inputStream.read(destMacBuffer);
                if (bytesRead != MAC_SIZE) {
                    if (bytesRead == -1) break;
                    continue;
                }


                byte[] srcMacBuffer = new byte[MAC_SIZE];
                bytesRead = inputStream.read(srcMacBuffer);
                if (bytesRead != MAC_SIZE) continue;


                byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
                bytesRead = inputStream.read(reqTypeBuffer);
                if (bytesRead != REQUEST_TYPE_SIZE) continue;

                byte[] destIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(destIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                byte[] srcIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(srcIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                byte[] dataLengthBuffer = new byte[4];
                bytesRead = inputStream.read(dataLengthBuffer);
                if (bytesRead != 4) continue;

                int dataLength = byteArrayToInt(dataLengthBuffer);
                if (dataLength > MAX_DATA_SIZE || dataLength < 0) {
                    dataLength = MAX_DATA_SIZE;
                }

                byte[] dataBuffer = new byte[dataLength];
                bytesRead = inputStream.read(dataBuffer);
                if (bytesRead != dataLength) continue;

                // Преобразуем все прочитанные байты в строки
                String destinationMAC = new String(destMacBuffer).trim();
                String sourceMAC = new String(srcMacBuffer).trim();
                byte requestType = reqTypeBuffer[0];
                String destinationIP = new String(destIpBuffer).trim();
                String sourceIP = new String(srcIpBuffer).trim();
                String data = new String(dataBuffer).trim();

                handleIncomingMessage(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);
            }
        } catch (IOException e) {
            if (!socket.isClosed()) {
                System.out.println("Соединение с маршрутизатором прервано: " + e.getMessage());
            }
        }
    }

    /**
     * Обрабатывает входящие пакеты в зависимости от их типа.
     *
     * @param destinationMAC MAC-адрес назначения
     * @param sourceMAC MAC-адрес отправителя
     * @param requestType тип запроса
     * @param destinationIP IP-адрес назначения
     * @param sourceIP IP-адрес отправителя
     * @param data данные пакета
     */
    private void handleIncomingMessage(String destinationMAC, String sourceMAC, byte requestType,
                                       String destinationIP, String sourceIP, String data) {
        // Получаем строковое представление типа запроса
        String requestTypeStr = getRequestTypeName(requestType);

        // Выводим информацию о полученном пакете
        String msg = String.format(
                "Клиент%d получил пакет -> DestMAC:%s, SrcMAC:%s, Type:%s, DestIP:%s, SrcIP:%s, Data:%s",
                clientNumber, destinationMAC, sourceMAC, requestTypeStr, destinationIP, sourceIP, data
        );
        System.out.println(msg);

        // Сохраняем MAC адрес источника в ARP таблицу (для всех не broadcast пакетов)
        if (!sourceMAC.equals("FF:FF:FF:FF:FF:FF") && !sourceIP.equals("0.0.0.0")) {
            tableARP.put(sourceIP, sourceMAC);  // Добавляем пару IP-MAC в таблицу
        }

        // Проверяем, предназначен ли пакет для нас
        if (destinationMAC.equals("FF:FF:FF:FF:FF:FF")) {
            // Для широковещательных пакетов проверяем тип
            if (requestType != DHCP_OFFER && requestType != DHCP_ACK &&
                    requestType != DHCP_AVAILABLE_IPS && requestType != ARP_REQUEST) {
                // Для остальных типов проверяем IP-назначения
                if (!destinationIP.equals("255.255.255.255") && !destinationIP.equals(CLIENT_IP) &&
                        !destinationIP.equals("0.0.0.0")) {
                    return;
                }
            }
        } else if (!destinationMAC.equals(CLIENT_MAC)) {
            // Если это не широковещательный и MAC не совпадает с нашим, игнорируем
            return;
        }

        // Передаем DNS-сообщения в DNSClient, если он инициализирован
        if (dnsClient != null && (requestType == DNS_ANNOUNCE || requestType == DNS_RESPONSE)) {
            dnsClient.handleDnsMessage(requestType, data, sourceMAC, sourceIP);
        }

        // Обрабатываем различные типы сообщений
        switch (requestType) {
            case DHCP_AVAILABLE_IPS: {
                // Получен список доступных IP-адресов
                if (!data.isEmpty()) {
                    // Парсим строку с IP-адресами, разделенными запятыми
                    String[] ips = data.split(",");
                    availableIPs = new ArrayList<>(Arrays.asList(ips));  // Сохраняем в список
                    System.out.println("Получен список доступных IP-адресов: " + String.join(", ", ips));
                }
                break;
            }
            case DHCP_OFFER: {
                // Получено предложение IP-адреса от DHCP-сервера
                if (dhcpOfferedIP == null) {  // Если мы еще не получили предложения
                    dhcpOfferedIP = data;  // Сохраняем предложенный IP
                    System.out.println("Получен DHCP Offer с IP: " + dhcpOfferedIP);
                }
                break;
            }
            case DHCP_ACK: {
                // Получено подтверждение выделения IP-адреса
                dhcpAckReceived = true;  // Устанавливаем флаг получения ACK
                System.out.println("Получен DHCP ACK для IP: " + data);
                break;
            }
            case ERROR: {
                System.out.println("Получена ошибка: " + data);
                break;
            }
            case PING: {
                // Получен ping-запрос, отвечаем pong
                System.out.println("Получен PING от " + sourceIP + ", отправляем PONG...");
                sendMessage(sourceMAC, CLIENT_MAC, PONG, sourceIP, CLIENT_IP, data);
                break;
            }
            case PONG: {
                // Получен pong-ответ на наш ping
                System.out.println("Получен PONG от " + sourceIP + " с сообщением: " + data);
                break;
            }
            case ARP_REQUEST: {
                // Получен ARP-запрос
                if (destinationIP.equals(CLIENT_IP)) {  // Если запрос о нашем IP
                    System.out.println("Получен ARP запрос от " + sourceIP + ", отправляем ответ...");
                    sendMessage(sourceMAC, CLIENT_MAC, ARP_RESPONSE, sourceIP, CLIENT_IP, CLIENT_MAC);
                }
                break;
            }
            case ARP_RESPONSE: {
                // Получен ARP-ответ
                if (destinationMAC.equals(CLIENT_MAC)) {
                    arpResponseMAC = data.isEmpty() ? sourceMAC : data;
                    System.out.println("Получен ARP ответ от " + sourceIP + " с MAC: " + arpResponseMAC);
                }
                break;
            }
            case HTTP_GET: {
                // Получен запрос на HTML-страницу
                System.out.println("Получен запрос на HTML-страницу от " + sourceIP);
                sendMessage(sourceMAC, CLIENT_MAC, HTTP_RESPONSE, sourceIP, CLIENT_IP, htmlPage);
                break;
            }
            case HTTP_RESPONSE: {
                // Получен ответ с HTML-страницей
                System.out.println("Получен HTTP ответ от " + sourceIP);
                System.out.println("Получена HTML-страница:");
                System.out.println("------- HTML НАЧАЛО -------");
                System.out.println(data);
                System.out.println("-------- HTML КОНЕЦ --------");
                break;
            }
        }
    }

    /**
     * Получает HTML-страницу по доменному имени или IP-адресу.
     * Если указано доменное имя, сначала разрешает его в IP-адрес.
     */
    private void getHtmlPage(String domainOrIp) {
        // Проверяем, есть ли у нас IP-адрес
        if (!ipAssigned) {
            System.out.println("Сначала необходимо получить IP-адрес");
            return;
        }

        String destinationIP = domainOrIp;  // Изначально предполагаем, что введен IP

        // Проверяем, является ли введенное значение IP-адресом
        if (!isValidIpAddress(domainOrIp)) {
            // Если не IP-адрес, считаем доменным именем и пытаемся разрешить
            String resolvedIP = dnsClient.resolveDomain(domainOrIp);

            if (resolvedIP == null) {  // Если не удалось разрешить
                System.out.println("Не удалось разрешить доменное имя: " + domainOrIp);
                return;
            }

            // Проверяем, что полученный IP правильного формата
            if (!isValidIpAddress(resolvedIP)) {
                System.out.println("Получен некорректный IP-адрес: " + resolvedIP);
                return;
            }

            destinationIP = resolvedIP;  // Используем разрешенный IP
            System.out.println("Доменное имя " + domainOrIp + " разрешено в IP: " + destinationIP);
        }

        // Получаем MAC адрес через ARP запрос
        String destinationMAC = getMacAddress(destinationIP);
        if (destinationMAC == null) {  // Если не удалось получить MAC
            System.out.println("ARP не удался. Не получилось узнать MAC для IP: " + destinationIP);
            return;
        }

        // Отправляем HTTP GET запрос
        System.out.println("Отправка HTTP GET запроса к " + domainOrIp + " (" + destinationIP + ")");
        sendMessage(destinationMAC, CLIENT_MAC, HTTP_GET, destinationIP, CLIENT_IP, "");
    }

    /**
     * Проверяет, является ли строка корректным IP-адресом.
     * Валидный IP-адрес состоит из четырех чисел от 0 до 255, разделенных точками.
     */
    private boolean isValidIpAddress(String ip) {
        try {
            // Проверяем наличие IP
            if (ip == null || ip.isEmpty()) return false;

            // Разбиваем на части по точкам
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {  // IP должен состоять из 4 частей
                return false;
            }

            // Проверяем каждую часть
            for (String part : parts) {
                int value = Integer.parseInt(part);  // Преобразуем в число
                if (value < 0 || value > 255) {  // Проверяем диапазон
                    return false;
                }
            }

            return true;  // Если все проверки пройдены, IP корректен
        } catch (NumberFormatException e) {
            return false;  // Если возникла ошибка при парсинге, IP некорректен
        }
    }

    /**
     * Отправляет сообщение
     *
     * @param destMAC MAC-адрес назначения
     * @param srcMAC MAC-адрес отправителя
     * @param reqType тип запроса
     * @param destIP IP-адрес назначения
     * @param srcIP IP-адрес отправителя
     * @param data данные для отправки
     */
    private void sendMessage(String destMAC, String srcMAC, byte reqType,
                             String destIP, String srcIP, String data) {
        try {
            // Подготавливаем поля пакета
            // Форматируем каждое поле до нужного размера
            byte[] destMACBytes = padRight(destMAC, MAC_SIZE).getBytes();  // MAC получателя
            byte[] srcMACBytes = padRight(srcMAC, MAC_SIZE).getBytes();    // MAC отправителя
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = reqType;  // Тип запроса
            byte[] destIPBytes = padRight(destIP, IP_SIZE).getBytes();     // IP получателя
            byte[] srcIPBytes = padRight(srcIP, IP_SIZE).getBytes();       // IP отправителя
            byte[] dataBytes = data.getBytes();  // Данные

            // Ограничиваем размер данных максимальным значением
            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);
                dataBytes = truncatedData;
            }

            // Записываем длину данных
            byte[] dataLengthBytes = intToByteArray(dataBytes.length);

            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush();

            String requestTypeStr = getRequestTypeName(reqType);  // Получаем строковое представление типа
            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destMAC +
                    " (IP: " + destIP + "), данные: " + data);

        } catch (IOException e) {
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());
        }
    }

    /**
     * Возвращает строковое представление типа сообщения по его коду.
     */
    private String getRequestTypeName(byte requestType) {
        switch (requestType) {
            case DHCP_DISCOVER: return "DHCP_DISCOVER";
            case DHCP_OFFER: return "DHCP_OFFER";
            case DHCP_REQUEST: return "DHCP_REQUEST";
            case DHCP_ACK: return "DHCP_ACK";
            case ERROR: return "ERROR";
            case DHCP_AVAILABLE_IPS: return "DHCP_AVAILABLE_IPS";
            case PING: return "PING";
            case PONG: return "PONG";
            case ARP_REQUEST: return "ARP_REQUEST";
            case ARP_RESPONSE: return "ARP_RESPONSE";
            case DNS_DISCOVER: return "DNS_DISCOVER";
            case DNS_ANNOUNCE: return "DNS_ANNOUNCE";
            case DNS_REGISTER: return "DNS_REGISTER";
            case DNS_RESOLVE: return "DNS_RESOLVE";
            case DNS_RESPONSE: return "DNS_RESPONSE";
            case HTTP_GET: return "HTTP_GET";
            case HTTP_RESPONSE: return "HTTP_RESPONSE";
            default: return "UNKNOWN(" + requestType + ")";
        }
    }


    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);  // Обрезаем, если длина больше требуемой
        }
        return String.format("%-" + n + "s", s);  // Дополняем пробелами справа
    }

    /**
     * Класс для работы с DNS в клиентских приложениях.
     * Позволяет находить DNS-серверы, регистрировать доменные имена и запрашивать IP по доменному имени.
     */
    private class DNSClient {
        //  DNS-серверы (IP  MAC)
        private final Map<String, String> dnsServers = new HashMap<>();  // Хранит пары IP-MAC найденных DNS-серверов

        // Кэш DNS-записей (домен  IP)
        private final Map<String, String> dnsCache = new HashMap<>();  // Хранит разрешенные доменные имена

        // Поля для хранения информации о клиенте
        private final String clientMAC;  // MAC-адрес клиента
        private final String clientIP;   // IP-адрес клиента

        // Выбранный DNS-сервер
        private String currentDnsServerIP = null;   // IP выбранного DNS-сервера
        private String currentDnsServerMAC = null;  // MAC выбранного DNS-сервера

        // Для асинхронного получения ответов
        private volatile String dnsResponseMessage = null;          // Хранит полученный ответ от DNS-сервера
        private volatile CountDownLatch dnsLatch = new CountDownLatch(1);

        private final SendMessageCallback sendMessageCallback;  //  для отправки сообщений

        /**
         * Интерфейс для функции отправки сообщения
         */
        public interface SendMessageCallback {
            void sendMessage(String destMAC, String srcMAC, byte reqType,
                             String destIP, String srcIP, String data);
        }

        /**
         * Создает новый экземпляр DNS-клиента
         *
         * @param clientMAC MAC-адрес клиента
         * @param clientIP IP-адрес клиента
         * @param sendMessageCallback для отправки сообщений через клиентский сокет
         */
        public DNSClient(String clientMAC, String clientIP, SendMessageCallback sendMessageCallback) {
            this.clientMAC = clientMAC;  // Сохраняем MAC-адрес клиента
            this.clientIP = clientIP;    // Сохраняем IP-адрес клиента
            this.sendMessageCallback = sendMessageCallback;  // Сохраняем отправки сообщений
        }

        /**
         * Обработка входящих DNS-сообщений. Этот метод должен вызываться из обработчика
         * входящих сообщений клиента при получении DNS-пакетов.
         *
         * @param requestType тип сообщения
         * @param data данные сообщения
         * @param sourceMAC MAC-адрес отправителя
         * @param sourceIP IP-адрес отправителя
         */
        public void handleDnsMessage(byte requestType, String data, String sourceMAC, String sourceIP) {
            switch (requestType) {
                case DNS_ANNOUNCE:
                    // Обнаружили DNS-сервер
                    handleDnsAnnounce(sourceMAC, sourceIP, data);
                    break;

                case DNS_RESPONSE:
                    // Получили ответ от DNS-сервера
                    handleDnsResponse(sourceMAC, sourceIP, data);
                    break;
            }
        }

        /**
         * Обработка объявления DNS-сервера
         *
         * @param serverMAC MAC-адрес DNS-сервера
         * @param serverIP IP-адрес DNS-сервера
         * @param data данные сообщения
         */
        private void handleDnsAnnounce(String serverMAC, String serverIP, String data) {
            System.out.println("Обнаружен DNS-сервер: " + serverIP + " (" + serverMAC + ")");
            // Сохраняем информацию о DNS-сервере
            dnsServers.put(serverIP, serverMAC);  // Добавляем пару IP-MAC в список серверов

            // Если у нас еще нет выбранного DNS-сервера, устанавливаем этот
            if (currentDnsServerIP == null) {
                currentDnsServerIP = serverIP;    // Запоминаем IP сервера
                currentDnsServerMAC = serverMAC;  // Запоминаем MAC сервера
                System.out.println("Установлен DNS-сервер по умолчанию: " + currentDnsServerIP);
            }
        }

        /**
         * Обработка ответа DNS-сервера
         *
         * @param serverMAC MAC-адрес DNS-сервера
         * @param serverIP IP-адрес DNS-сервера
         * @param data данные сообщения
         */
        private void handleDnsResponse(String serverMAC, String serverIP, String data) {
            System.out.println("Получен ответ от DNS-сервера: " + data);
            dnsResponseMessage = data;  // Сохраняем полученное сообщение
            dnsLatch.countDown();       // Разблокируем ожидающий поток

            // Парсим и сохраняем результат в кэш, если это успешный ответ на RESOLVE
            if (data.startsWith("DNS RESOLVE OK")) {
                String[] parts = data.split("\\s+");  // Разделяем сообщение на части по пробелам
                if (parts.length >= 5) {  // Должно быть не менее 5 частей
                    String domain = parts[3];  // Четвертый элемент - это домен
                    String ip = parts[4];      // Пятый элемент - это IP
                    System.out.println("Добавлен в кэш: " + domain + " -> " + ip);
                    dnsCache.put(domain, ip);  // Сохраняем домен - IP в кэш
                }
            }
        }

        /**
         * Поиск DNS-серверов в сети
         */
        public void discoverDnsServers() {
            System.out.println("Поиск DNS-серверов в сети...");
            // Отправляем широковещательный запрос для обнаружения DNS-серверов
            sendMessageCallback.sendMessage(
                    "FF:FF:FF:FF:FF:FF", clientMAC, DNS_DISCOVER,
                    "255.255.255.255", clientIP, "DNS_DISCOVER"
            );

            // Даем время на получение ответов
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            // Выводим обнаруженные серверы
            if (dnsServers.isEmpty()) {
                System.out.println("DNS-серверы не обнаружены");
            } else {
                System.out.println("Обнаружены DNS-серверы:");
                int i = 1;
                for (Map.Entry<String, String> entry : dnsServers.entrySet()) {
                    System.out.println(i++ + ". " + entry.getKey() + " (" + entry.getValue() + ")");
                }
            }
        }

        /**
         * Выбор DNS-сервера для использования
         *
         * @param serverIP IP-адрес DNS-сервера
         * @return true, если сервер успешно выбран, иначе false
         */
        public boolean selectDnsServer(String serverIP) {
            if (dnsServers.containsKey(serverIP)) {  // Если сервер есть в списке
                currentDnsServerIP = serverIP;                     // Запоминаем IP
                currentDnsServerMAC = dnsServers.get(serverIP);    // Запоминаем MAC
                System.out.println("Выбран DNS-сервер: " + currentDnsServerIP);
                return true;
            }
            return false;
        }

        /**
         * Регистрация доменного имени
         *
         * @param domain доменное имя
         * @param ip IP-адрес для этого домена
         * @return true, если домен успешно зарегистрирован, иначе false
         */
        public boolean registerDomain(String domain, String ip) {
            if (currentDnsServerIP == null) {  // Если не выбран DNS-сервер
                System.out.println("DNS-сервер не выбран. Запустите discoverDnsServers() сначала.");
                return false;
            }

            // Сбрасываем данные предыдущего ответа
            dnsResponseMessage = null;
            dnsLatch = new CountDownLatch(1);

            // Подготавливаем запрос на регистрацию
            String registerCommand = "DNS REGISTER " + domain + " " + ip;
            System.out.println("Отправка запроса на регистрацию: " + registerCommand);

            // Отправляем запрос на регистрацию
            sendMessageCallback.sendMessage(
                    currentDnsServerMAC, clientMAC, DNS_REGISTER,
                    currentDnsServerIP, clientIP, registerCommand
            );

            try {
                dnsLatch.await();  // Ждем, пока придет ответ
            } catch (InterruptedException e) {
                e.printStackTrace();
                return false;
            }

            // Проверяем ответ
            if (dnsResponseMessage != null && dnsResponseMessage.contains("DNS REGISTER OK")) {
                System.out.println("Домен успешно зарегистрирован: " + domain + " -> " + ip);
                // Добавляем в локальный кэш
                dnsCache.put(domain, ip);  // Сохраняем домен - IP в кэш
                return true;
            } else {
                System.out.println("Ошибка регистрации домена: " +
                        (dnsResponseMessage != null ? dnsResponseMessage : "нет ответа"));
                return false;
            }
        }

        /**
         * Поиск IP по доменному имени
         *
         * @param domain доменное имя
         * @return IP-адрес или null, если не удалось разрешить
         */
        public String resolveDomain(String domain) {
            // Сначала проверяем локальный кэш
            if (dnsCache.containsKey(domain)) {
                String ip = dnsCache.get(domain);  // Получаем IP из кэша
                System.out.println("Найдено в кэше: " + domain + " -> " + ip);
                return ip;
            }

            if (currentDnsServerIP == null) {  // Если не выбран DNS-сервер
                System.out.println("DNS-сервер не выбран. Запустите discoverDnsServers() сначала.");
                return null;
            }

            // Сбрасываем данные предыдущего ответа
            dnsResponseMessage = null;
            dnsLatch = new CountDownLatch(1);  // Создаем новый синхронизатор

            // Подготавливаем запрос на разрешение
            String resolveCommand = "DNS RESOLVE " + domain;
            System.out.println("Отправка запроса на разрешение: " + resolveCommand);

            // Отправляем запрос на разрешение
            sendMessageCallback.sendMessage(
                    currentDnsServerMAC, clientMAC, DNS_RESOLVE,
                    currentDnsServerIP, clientIP, resolveCommand
            );

            try {
                dnsLatch.await();  // Ждем, пока придет ответ
            } catch (InterruptedException e) {
                e.printStackTrace();
                return null;
            }

            // Проверяем ответ
            if (dnsResponseMessage != null && dnsResponseMessage.contains("DNS RESOLVE OK")) {
                String[] parts = dnsResponseMessage.split("\\s+");  // Разделяем сообщение на части
                if (parts.length >= 5) {  // Должно быть не менее 5 частей
                    String resolvedDomain = parts[3];  // Получаем домен
                    String resolvedIP = parts[4];      // Получаем IP

                    System.out.println("Домен успешно разрешен: " + domain + " -> " + resolvedIP);
                    dnsCache.put(domain, resolvedIP);  // Сохраняем в кэш
                    return resolvedIP;
                }
            }

            System.out.println("Домен не найден: " + domain);
            return null;
        }

        /**
         * Получить список известных DNS-серверов
         *
         * @return неизменяемая карта IP - MAC DNS-серверов
         */
        public Map<String, String> getDnsServers() {
            return Collections.unmodifiableMap(dnsServers);
        }

        /**
         * Получить список записей в кэше
         *
         * @return неизменяемая карта доменное имя - IP
         */
        public Map<String, String> getDnsCache() {
            return Collections.unmodifiableMap(dnsCache);
        }
    }
}