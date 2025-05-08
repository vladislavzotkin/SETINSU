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

public class Client2 {

    // Размеры полей в байтах
    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;

    // Коды сообщений
    private static final byte DHCP_DISCOVER = 5;
    private static final byte DHCP_OFFER = 6;
    private static final byte DHCP_REQUEST = 7;
    private static final byte DHCP_ACK = 8;
    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10;

    // Типы пользовательских сообщений
    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;
    private static final byte ARP_RESPONSE = 23;

    // DNS коды сообщений
    private static final byte DNS_DISCOVER = 30;
    private static final byte DNS_ANNOUNCE = 31;
    private static final byte DNS_REGISTER = 32;
    private static final byte DNS_RESOLVE = 33;
    private static final byte DNS_RESPONSE = 34;

    private static String CLIENT_MAC;
    private static String CLIENT_IP = "0.0.0.0"; // Изначально нет IP
    private static boolean ipAssigned = false;   // Флаг успешного получения IP

    private static String ROUTER_ADDRESS;
    private static int ROUTER_PORT;
    private static final String ROUTER_MAC = "AA:BB:CC:DD:EE:FF"; // MAC маршрутизатора

    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;
    private volatile String dhcpOfferedIP = null; // IP предложенный через DHCP
    private volatile List<String> availableIPs = new ArrayList<>(); // Список доступных IP
    private volatile boolean dhcpAckReceived = false; // Флаг получения DHCP ACK
    private volatile CountDownLatch dhcpLatch = new CountDownLatch(1);

    // IP - MAC таблица (ARP)
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());
    private volatile String arpResponseMAC = null; // MAC в ответ на ARP запрос

    private DNSClient dnsClient;

    private static final byte HTTP_GET = 40;   // Запрос HTML-страницы
    private static final byte HTTP_RESPONSE = 41;   // Ответ с HTML-страницей

    private int clientNumber;
    private boolean manualIPSelection; // Флаг для ручного выбора IP
    private String htmlPage;



    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        int clientNumber = 2;

        System.out.println("Введите MAC адрес клиента (или нажмите Enter для AA:BB:CC:DD:EE:0" + clientNumber + "):");
        CLIENT_MAC = scanner.nextLine();
        if (CLIENT_MAC.isEmpty()) {
            CLIENT_MAC = "AA:BB:CC:DD:EE:0" + clientNumber;
        }

        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для 127.0.0.1):");
        ROUTER_ADDRESS = scanner.nextLine();
        if (ROUTER_ADDRESS.isEmpty()) {
            ROUTER_ADDRESS = "127.0.0.1";
        }

        System.out.println("Введите порт маршрутизатора (или нажмите Enter для 8081):");
        String portInput = scanner.nextLine();
        ROUTER_PORT = portInput.isEmpty() ? 8081 : Integer.parseInt(portInput);

        System.out.println("Хотите вручную выбрать IP-адрес? (true/false):");
        boolean manualIPSelection = Boolean.parseBoolean(scanner.nextLine());

        Client2 client = new Client2();
        client.clientNumber = clientNumber;
        client.manualIPSelection = manualIPSelection;
        client.start(scanner);
    }

    public void start(Scanner scanner) {
        try {
            // Подключение к роутеру
            socket = new Socket(ROUTER_ADDRESS, ROUTER_PORT);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            System.out.println("Клиент " + clientNumber + " подключился к " + ROUTER_ADDRESS + ":" + ROUTER_PORT);

            // Запускаем поток для прослушивания входящих сообщений
            Thread listenThread = new Thread(this::listenForMessages);
            listenThread.setDaemon(true);
            listenThread.start();

            // Запускаем процесс получения IP через DHCP
            Thread.sleep(1000); // Даем время на подключение
            performDhcpProcess(scanner);

            if (!ipAssigned) {
                System.out.println("Не удалось получить IP-адрес через DHCP");
                socket.close();
                return;
            }

            System.out.println("IP-адрес " + CLIENT_IP + " успешно получен через DHCP");

            // Инициализируем DNS-клиент
            dnsClient = new DNSClient(CLIENT_MAC, CLIENT_IP, this::sendMessage);
            System.out.println("DNS-клиент инициализирован");


            // Расширенное меню для пользователя с добавленным функционалом
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

                if (choice.equals("1")) {
                    System.out.println("Информация о клиенте:");
                    System.out.println("Номер клиента: " + clientNumber);
                    System.out.println("MAC-адрес: " + CLIENT_MAC);
                    System.out.println("IP-адрес: " + CLIENT_IP);
                    System.out.println("Статус: " + (ipAssigned ? "IP назначен" : "IP не назначен"));
                }
                else if (choice.equals("2")) {
                    System.out.println("Запуск нового DHCP запроса...");
                    // Сбрасываем состояние
                    dhcpOfferedIP = null;
                    availableIPs.clear();
                    dhcpAckReceived = false;
                    ipAssigned = false;
                    CLIENT_IP = "0.0.0.0";
                    dhcpLatch = new CountDownLatch(1);

                    // Запускаем процесс получения IP
                    performDhcpProcess(scanner);
                }
                else if (choice.equals("3")) {
                    // Новый функционал: отправка сообщений другим клиентам
                    if (!ipAssigned) {
                        System.out.println("Сначала необходимо получить IP-адрес");
                        continue;
                    }

                    System.out.println("Введите IP адрес или доменное имя назначения:");
                    String destination = scanner.nextLine();
                    String destinationIP = destination;

                    // Проверяем, является ли это доменным именем
                    if (!destination.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                        // Это доменное имя, пытаемся разрешить
                        destinationIP = dnsClient.resolveDomain(destination);
                        if (destinationIP == null) {
                            System.out.println("Не удалось разрешить доменное имя: " + destination);
                            continue;
                        }
                        System.out.println("Доменное имя " + destination + " разрешено в IP: " + destinationIP);
                    }

                    System.out.print("Введите сообщение: ");
                    String data = scanner.nextLine();

                    // Получаем MAC адрес через ARP запрос если нужно
                    String destinationMAC = getMacAddress(destinationIP);
                    if (destinationMAC == null) {
                        System.out.println("ARP не удался. Не получилось узнать MAC для IP: " + destinationIP);
                        continue;
                    }

                    sendMessage(destinationMAC, CLIENT_MAC, PING, destinationIP, CLIENT_IP, data);
                    System.out.println("Сообщение отправлено");
                }
                else if (choice.equals("4")) {
                    // Новый функционал: просмотр ARP таблицы
                    System.out.println("ARP таблица:");
                    if (tableARP.isEmpty()) {
                        System.out.println("Таблица пуста");
                    } else {
                        for (Map.Entry<String, String> entry : tableARP.entrySet()) {
                            System.out.println("IP: " + entry.getKey() + " -> MAC: " + entry.getValue());
                        }
                    }
                }
                else if (choice.equals("5")) {
                    // Управление DNS
                    showDnsMenu(scanner);
                }
                else if (choice.equals("6")) {
                    System.out.print("Введите доменное имя или IP-адрес: ");
                    String domain = scanner.nextLine();
                    getHtmlPage(domain);
                }
                else if (choice.equals("7")) {
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

    private void initializeHtmlPage() {
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



    // Меню для управления DNS
    private void showDnsMenu(Scanner scanner) {
        if (!ipAssigned) {
            System.out.println("Сначала необходимо получить IP-адрес");
            return;
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

            if (choice.equals("1")) {
                // Поиск DNS-серверов
                dnsClient.discoverDnsServers();
            }
            else if (choice.equals("2")) {
                // Выбрать DNS-сервер
                Map<String, String> servers = dnsClient.getDnsServers();
                if (servers.isEmpty()) {
                    System.out.println("Нет доступных DNS-серверов. Выполните поиск сначала.");
                    continue;
                }

                System.out.println("Доступные DNS-серверы:");
                int i = 1;
                String[] serverIPs = new String[servers.size()];
                for (String ip : servers.keySet()) {
                    System.out.println(i + ". " + ip + " (" + servers.get(ip) + ")");
                    serverIPs[i-1] = ip;
                    i++;
                }

                System.out.print("Выберите номер сервера: ");
                try {
                    int serverIdx = Integer.parseInt(scanner.nextLine());
                    if (serverIdx >= 1 && serverIdx <= serverIPs.length) {
                        dnsClient.selectDnsServer(serverIPs[serverIdx-1]);
                    } else {
                        System.out.println("Неверный номер");
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Пожалуйста, введите число");
                }
            }
            else if (choice.equals("3")) {
                // Зарегистрировать доменное имя
                System.out.print("Введите доменное имя: ");
                String domain = scanner.nextLine();

                System.out.print("Введите IP-адрес (или нажмите Enter для " + CLIENT_IP + "): ");
                String ip = scanner.nextLine();
                if (ip.isEmpty()) {
                    ip = CLIENT_IP;
                }

                dnsClient.registerDomain(domain, ip);
            }
            else if (choice.equals("4")) {
                // Найти IP по доменному имени
                System.out.print("Введите доменное имя: ");
                String domain = scanner.nextLine();

                String ip = dnsClient.resolveDomain(domain);
                if (ip != null) {
                    System.out.println("IP-адрес для " + domain + ": " + ip);
                } else {
                    System.out.println("Не удалось разрешить домен " + domain);
                }
            }
            else if (choice.equals("5")) {
                // Показать кэш DNS
                Map<String, String> cache = dnsClient.getDnsCache();
                if (cache.isEmpty()) {
                    System.out.println("DNS-кэш пуст");
                } else {
                    System.out.println("DNS-кэш:");
                    int i = 1;
                    for (Map.Entry<String, String> entry : cache.entrySet()) {
                        System.out.println(i++ + ". " + entry.getKey() + " -> " + entry.getValue());
                    }
                }
            }
            else if (choice.equals("6")) {
                return; // Возврат в главное меню
            }
            else {
                System.out.println("Неверный выбор, попробуйте снова");
            }
        }
    }

    // Выполнение процесса DHCP для получения IP-адреса
    private void performDhcpProcess(Scanner scanner) {
        try {
            // Отправляем DHCP Discover
            System.out.println("Отправка DHCP Discover...");
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_DISCOVER, "255.255.255.255", "0.0.0.0", "");

            // Ждем получения информации от сервера
            Thread.sleep(3000); // Ждем 3 секунды

            // Выбираем IP-адрес
            String requestedIP = null;

            if (dhcpOfferedIP != null) {
                // Если получили предложение IP через DHCP Offer, используем его
                requestedIP = dhcpOfferedIP;
                System.out.println("Используем предложенный IP: " + requestedIP);
            } else if (!availableIPs.isEmpty()) {
                // Если получили список доступных IP, но не получили DHCP Offer
                if (manualIPSelection) {
                    // Показываем доступные IP и запрашиваем выбор пользователя
                    System.out.println("\nДоступные IP-адреса:");
                    for (int i = 0; i < availableIPs.size(); i++) {
                        System.out.println((i + 1) + ". " + availableIPs.get(i));
                    }

                    int choice = -1;
                    while (choice < 1 || choice > availableIPs.size()) {
                        System.out.print("Выберите IP (1-" + availableIPs.size() + "): ");
                        try {
                            choice = Integer.parseInt(scanner.nextLine());
                        } catch (NumberFormatException e) {
                            System.out.println("Пожалуйста, введите число");
                        }
                    }

                    requestedIP = availableIPs.get(choice - 1);
                    System.out.println("Выбран IP: " + requestedIP);
                } else {
                    // Автоматически выбираем первый доступный IP
                    requestedIP = availableIPs.get(0);
                    System.out.println("Автоматически выбран первый доступный IP: " + requestedIP);
                }
            } else {
                System.out.println("Не получен ни DHCP Offer, ни список доступных IP, процесс не завершен");
                return;
            }

            // Отправляем DHCP Request
            System.out.println("Отправка DHCP Request для IP: " + requestedIP);
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_REQUEST, "255.255.255.255", "0.0.0.0", requestedIP);

            // Ждем DHCP ACK
            Thread.sleep(3000); // Ждем 3 секунды

            if (dhcpAckReceived) {
                CLIENT_IP = requestedIP;
                ipAssigned = true;
                System.out.println("DHCP процесс завершен успешно, получен IP: " + CLIENT_IP);
                // Инициализируем HTML-страницу
                initializeHtmlPage();
            } else {
                System.out.println("Не получен DHCP ACK, процесс не завершен");
            }

        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    // Получение MAC из таблицы, если нет, то запрашиваем через ARP
    private String getMacAddress(String ip) {
        if (tableARP.containsKey(ip)) {
            return tableARP.get(ip);
        } else {
            // Отправляем ARP запрос
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, ARP_REQUEST, ip, CLIENT_IP, "");

            // Ждем пока придёт ARP response
            try {
                int tries = 0; // количество попыток
                while (arpResponseMAC == null && tries < 10) {
                    Thread.sleep(200);
                    tries++;
                }
                if (arpResponseMAC != null) {
                    String mac = arpResponseMAC;
                    arpResponseMAC = null; // сбрасываем для следующего запроса
                    tableARP.put(ip, mac);
                    return mac;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    // Преобразование массива байтов в целое число
    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    // Преобразование целого числа в массив байтов
    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    // Прослушивание входящих сообщений от маршрутизатора
    private void listenForMessages() {
        try {
            while (true) {
                // Читаем MAC-адрес назначения
                byte[] destMacBuffer = new byte[MAC_SIZE];
                int bytesRead = inputStream.read(destMacBuffer);
                if (bytesRead != MAC_SIZE) {
                    if (bytesRead == -1) break; // Конец потока
                    continue; // Неверный размер
                }

                // Читаем MAC-адрес отправителя
                byte[] srcMacBuffer = new byte[MAC_SIZE];
                bytesRead = inputStream.read(srcMacBuffer);
                if (bytesRead != MAC_SIZE) continue;

                // Читаем тип запроса (1 байт)
                byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
                bytesRead = inputStream.read(reqTypeBuffer);
                if (bytesRead != REQUEST_TYPE_SIZE) continue;

                // Читаем IP-адрес назначения
                byte[] destIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(destIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                // Читаем IP-адрес отправителя
                byte[] srcIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(srcIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                // Читаем длину данных (4 байта)
                byte[] dataLengthBuffer = new byte[4];
                bytesRead = inputStream.read(dataLengthBuffer);
                if (bytesRead != 4) continue;

                int dataLength = byteArrayToInt(dataLengthBuffer);
                if (dataLength > MAX_DATA_SIZE || dataLength < 0) {
                    dataLength = MAX_DATA_SIZE; // Ограничиваем размер
                }

                // Читаем данные
                byte[] dataBuffer = new byte[dataLength];
                bytesRead = inputStream.read(dataBuffer);
                if (bytesRead != dataLength) continue;

                // Преобразуем все в строки
                String destinationMAC = new String(destMacBuffer).trim();
                String sourceMAC = new String(srcMacBuffer).trim();
                byte requestType = reqTypeBuffer[0]; // Получаем код сообщения
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

    // Обработка входящих пакетов
    private void handleIncomingMessage(String destinationMAC, String sourceMAC, byte requestType,
                                       String destinationIP, String sourceIP, String data) {
        String requestTypeStr = getRequestTypeName(requestType);
        String msg = String.format(
                "Клиент%d получил пакет -> DestMAC:%s, SrcMAC:%s, Type:%s, DestIP:%s, SrcIP:%s, Data:%s",
                clientNumber, destinationMAC, sourceMAC, requestTypeStr, destinationIP, sourceIP, data
        );
        System.out.println(msg);

        // Сохраняем MAC адрес источника в ARP таблицу (для всех не broadcast пакетов)
        if (!sourceMAC.equals("FF:FF:FF:FF:FF:FF") && !sourceIP.equals("0.0.0.0")) {
            tableARP.put(sourceIP, sourceMAC);
        }

        // Проверяем, что пакет предназначен для нас
        if (destinationMAC.equals("FF:FF:FF:FF:FF:FF")) {
            // Для DHCP и ARP принимаем широковещательные сообщения
            if (requestType != DHCP_OFFER && requestType != DHCP_ACK &&
                    requestType != DHCP_AVAILABLE_IPS && requestType != ARP_REQUEST) {
                if (!destinationIP.equals("255.255.255.255") && !destinationIP.equals(CLIENT_IP) &&
                        !destinationIP.equals("0.0.0.0")) {
                    return; // Не для нас
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

        // Обрабатываем сообщения по типу
        switch (requestType) {
            case DHCP_AVAILABLE_IPS: {
                if (!data.isEmpty()) {
                    // Парсим список доступных IP
                    String[] ips = data.split(",");
                    availableIPs = new ArrayList<>(Arrays.asList(ips));
                    System.out.println("Получен список доступных IP-адресов: " + String.join(", ", ips));
                }
                break;
            }
            case DHCP_OFFER: {
                if (dhcpOfferedIP == null) {
                    dhcpOfferedIP = data; // Сохраняем предложенный IP
                    System.out.println("Получен DHCP Offer с IP: " + dhcpOfferedIP);
                }
                break;
            }
            case DHCP_ACK: {
                dhcpAckReceived = true;
                System.out.println("Получен DHCP ACK для IP: " + data);
                break;
            }
            case ERROR: {
                System.out.println("Получена ошибка: " + data);
                break;
            }
            case PING: {
                // Отвечаем PONG на входящий PING
                System.out.println("Получен PING от " + sourceIP + ", отправляем PONG...");
                sendMessage(sourceMAC, CLIENT_MAC, PONG, sourceIP, CLIENT_IP, data);
                break;
            }
            case PONG: {
                System.out.println("Получен PONG от " + sourceIP + " с сообщением: " + data);
                break;
            }
            case ARP_REQUEST: {
                // Отвечаем на ARP запрос, если он для нашего IP
                if (destinationIP.equals(CLIENT_IP)) {
                    System.out.println("Получен ARP запрос от " + sourceIP + ", отправляем ответ...");
                    sendMessage(sourceMAC, CLIENT_MAC, ARP_RESPONSE, sourceIP, CLIENT_IP, CLIENT_MAC);
                }
                break;
            }
            case ARP_RESPONSE: {
                // Получаем MAC из ответа
                if (destinationMAC.equals(CLIENT_MAC)) {
                    arpResponseMAC = data.isEmpty() ? sourceMAC : data;
                    System.out.println("Получен ARP ответ от " + sourceIP + " с MAC: " + arpResponseMAC);
                }
                break;
            }
            case HTTP_GET: {
                // Отвечаем на запрос HTML страницы
                System.out.println("Получен запрос на HTML-страницу от " + sourceIP);
                sendMessage(sourceMAC, CLIENT_MAC, HTTP_RESPONSE, sourceIP, CLIENT_IP, htmlPage);
                break;
            }
            case HTTP_RESPONSE: {
                System.out.println("Получен HTTP ответ от " + sourceIP);
                System.out.println("Получена HTML-страница:");
                System.out.println("------- HTML НАЧАЛО -------");
                System.out.println(data);
                System.out.println("-------- HTML КОНЕЦ --------");
                break;
            }
        }
    }

    private void getHtmlPage(String domainOrIp) {
        if (!ipAssigned) {
            System.out.println("Сначала необходимо получить IP-адрес");
            return;
        }

        String destinationIP = domainOrIp;

        // Проверяем, является ли это доменным именем или IP-адресом
        if (!isValidIpAddress(domainOrIp)) {
            // Это доменное имя, пытаемся разрешить
            String resolvedIP = dnsClient.resolveDomain(domainOrIp);

            if (resolvedIP == null) {
                System.out.println("Не удалось разрешить доменное имя: " + domainOrIp);
                return;
            }

            // Проверяем, что полученный IP правильного формата
            if (!isValidIpAddress(resolvedIP)) {
                System.out.println("Получен некорректный IP-адрес: " + resolvedIP);
                return;
            }

            destinationIP = resolvedIP;
            System.out.println("Доменное имя " + domainOrIp + " разрешено в IP: " + destinationIP);
        }

        // Получаем MAC адрес через ARP запрос
        String destinationMAC = getMacAddress(destinationIP);
        if (destinationMAC == null) {
            System.out.println("ARP не удался. Не получилось узнать MAC для IP: " + destinationIP);
            return;
        }

        // Отправляем HTTP GET запрос
        System.out.println("Отправка HTTP GET запроса к " + domainOrIp + " (" + destinationIP + ")");
        sendMessage(destinationMAC, CLIENT_MAC, HTTP_GET, destinationIP, CLIENT_IP, "");
    }
    // Вспомогательный метод для проверки формата IP-адреса
    private boolean isValidIpAddress(String ip) {
        try {
            if (ip == null || ip.isEmpty()) return false;

            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }

            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            }

            return true;
        } catch (NumberFormatException e) {
            return false;
        }

    }

    private void sendMessage(String destMAC, String srcMAC, byte reqType,
                             String destIP, String srcIP, String data) {
        try {
            // Форматируем каждое поле до нужного размера
            byte[] destMACBytes = padRight(destMAC, MAC_SIZE).getBytes();
            byte[] srcMACBytes = padRight(srcMAC, MAC_SIZE).getBytes();
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = reqType; // Записываем код
            byte[] destIPBytes = padRight(destIP, IP_SIZE).getBytes();
            byte[] srcIPBytes = padRight(srcIP, IP_SIZE).getBytes();
            byte[] dataBytes = data.getBytes();

            // Ограничиваем размер данных
            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);
                dataBytes = truncatedData;
            }

            // Записываем длину данных (4 байта)
            byte[] dataLengthBytes = intToByteArray(dataBytes.length);

            // Записываем все поля последовательно
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush();

            // Выводим отладочную информацию
            String requestTypeStr = getRequestTypeName(reqType);

            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destMAC +
                    " (IP: " + destIP + "), данные: " + data);

        } catch (IOException e) {
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());
        }
    }

    // Получение строкового представления типа сообщения
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

    // Дополняем строку пробелами до нужной длины
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }

    /**
     * Класс для работы с DNS в клиентских приложениях.
     * Позволяет находить DNS-сервер, регистрировать доменные имена и запрашивать IP по доменному имени.
     */
    private class DNSClient {
        // Известные DNS-серверы (IP → MAC)
        private final Map<String, String> dnsServers = new HashMap<>();

        // Кэш DNS-записей (домен → IP)
        private final Map<String, String> dnsCache = new HashMap<>();

        // Поля для хранения информации о клиенте
        private final String clientMAC;
        private final String clientIP;

        // Выбранный DNS-сервер
        private String currentDnsServerIP = null;
        private String currentDnsServerMAC = null;

        // Для асинхронного получения ответов
        private volatile String dnsResponseMessage = null;
        private volatile CountDownLatch dnsLatch = new CountDownLatch(1);

        // Вспомогательная функция для отправки сообщений
        private final SendMessageCallback sendMessageCallback;

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
         * @param sendMessageCallback функция для отправки сообщений через клиентский сокет
         */
        public DNSClient(String clientMAC, String clientIP, SendMessageCallback sendMessageCallback) {
            this.clientMAC = clientMAC;
            this.clientIP = clientIP;
            this.sendMessageCallback = sendMessageCallback;
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
         */
        private void handleDnsAnnounce(String serverMAC, String serverIP, String data) {
            System.out.println("Обнаружен DNS-сервер: " + serverIP + " (" + serverMAC + ")");
            // Сохраняем информацию о DNS-сервере
            dnsServers.put(serverIP, serverMAC);

            // Если у нас еще нет выбранного DNS-сервера, устанавливаем этот
            if (currentDnsServerIP == null) {
                currentDnsServerIP = serverIP;
                currentDnsServerMAC = serverMAC;
                System.out.println("Установлен DNS-сервер по умолчанию: " + currentDnsServerIP);
            }
        }

        /**
         * Обработка ответа DNS-сервера
         */
        private void handleDnsResponse(String serverMAC, String serverIP, String data) {
            System.out.println("Получен ответ от DNS-сервера: " + data);
            dnsResponseMessage = data;
            dnsLatch.countDown(); // Разблокируем ожидающий поток

            // Парсим и сохраняем результат в кэш, если это успешный ответ на RESOLVE
            if (data.startsWith("DNS RESOLVE OK")) {
                String[] parts = data.split("\\s+");
                if (parts.length >= 5) { // Должно быть не менее 5 частей
                    String domain = parts[3]; // Четвертый элемент - это домен
                    String ip = parts[4]; // Пятый элемент - это IP
                    System.out.println("Добавлен в кэш: " + domain + " -> " + ip);
                    dnsCache.put(domain, ip); // Сохраняем домен - IP
                }
            }
        }
        /**
         * Поиск DNS-серверов в сети
         */
        public void discoverDnsServers() {
            System.out.println("Поиск DNS-серверов в сети...");
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
         */
        public boolean selectDnsServer(String serverIP) {
            if (dnsServers.containsKey(serverIP)) {
                currentDnsServerIP = serverIP;
                currentDnsServerMAC = dnsServers.get(serverIP);
                System.out.println("Выбран DNS-сервер: " + currentDnsServerIP);
                return true;
            }
            return false;
        }

        /**
         * Регистрация доменного имени
         */
        public boolean registerDomain(String domain, String ip) {
            if (currentDnsServerIP == null) {
                System.out.println("DNS-сервер не выбран. Запустите discoverDnsServers() сначала.");
                return false;
            }

            // Сбрасываем данные предыдущего ответа
            dnsResponseMessage = null;
            dnsLatch = new CountDownLatch(1);

            // Отправляем запрос на регистрацию
            String registerCommand = "DNS REGISTER " + domain + " " + ip;
            System.out.println("Отправка запроса на регистрацию: " + registerCommand);

            sendMessageCallback.sendMessage(
                    currentDnsServerMAC, clientMAC, DNS_REGISTER,
                    currentDnsServerIP, clientIP, registerCommand
            );

            // Ждем ответа
            try {
                dnsLatch.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
                return false;
            }

            // Проверяем ответ
            if (dnsResponseMessage != null && dnsResponseMessage.contains("DNS REGISTER OK")) {
                System.out.println("Домен успешно зарегистрирован: " + domain + " -> " + ip);
                // Добавляем в локальный кэш
                dnsCache.put(domain, ip);
                return true;
            } else {
                System.out.println("Ошибка регистрации домена: " +
                        (dnsResponseMessage != null ? dnsResponseMessage : "нет ответа"));
                return false;
            }
        }

        /**
         * Поиск IP по доменному имени
         */
        public String resolveDomain(String domain) {
            // Сначала проверяем локальный кэш
            if (dnsCache.containsKey(domain)) {
                String ip = dnsCache.get(domain);
                System.out.println("Найдено в кэше: " + domain + " -> " + ip);
                return ip;
            }

            if (currentDnsServerIP == null) {
                System.out.println("DNS-сервер не выбран. Запустите discoverDnsServers() сначала.");
                return null;
            }

            // Сбрасываем данные предыдущего ответа
            dnsResponseMessage = null;
            dnsLatch = new CountDownLatch(1);

            // Отправляем запрос на разрешение
            String resolveCommand = "DNS RESOLVE " + domain;
            System.out.println("Отправка запроса на разрешение: " + resolveCommand);

            sendMessageCallback.sendMessage(
                    currentDnsServerMAC, clientMAC, DNS_RESOLVE,
                    currentDnsServerIP, clientIP, resolveCommand
            );

            // Ждем ответа
            try {
                dnsLatch.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
                return null;
            }

            // Проверяем ответ
            if (dnsResponseMessage != null && dnsResponseMessage.contains("DNS RESOLVE OK")) {
                String[] parts = dnsResponseMessage.split("\\s+");
                if (parts.length >= 5) { // Должно быть не менее 5 частей
                    String resolvedDomain = parts[3]; // Получаем домен
                    String resolvedIP = parts[4]; // Получаем IP

                    System.out.println("Домен успешно разрешен: " + domain + " -> " + resolvedIP);
                    dnsCache.put(domain, resolvedIP); // Сохраняем в кэш
                    return resolvedIP;
                }
            }

            System.out.println("Домен не найден: " + domain);
            return null;
        }
        /**
         * Получить список известных DNS-серверов
         */
        public Map<String, String> getDnsServers() {
            return Collections.unmodifiableMap(dnsServers);
        }

        /**
         * Получить список записей в кэше
         */
        public Map<String, String> getDnsCache() {
            return Collections.unmodifiableMap(dnsCache);
        }
    }
}