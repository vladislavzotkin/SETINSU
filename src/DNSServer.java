import java.io.*;      
import java.net.*;      
import java.util.*;      
import java.util.concurrent.CountDownLatch; 

/**
 * Поддерживает регистрацию доменов, разрешение имён в IP адреса и обнаружение сервера другими узлами.
 * Получает IP адрес через DHCP или вручную, поддерживает ARP для определения MAC адресов.
 */
public class DNSServer {
    /* Размер поля MAC адреса в байтах (включая разделители) */
    private static final int MAC_SIZE = 17;
    /* Размер поля типа запроса в байтах */
    private static final int REQUEST_TYPE_SIZE = 1;
    /* Размер поля IP-адреса в байтах */
    private static final int IP_SIZE = 15;
    /* Максимальный размер данных в пакете */
    private static final int MAX_DATA_SIZE = 1024;

    /** DHCP DISCOVER -запрашивает IP-адрес */
    private static final byte DHCP_DISCOVER = 5;
    /**  DHCP OFFER - DHCP сервер предлагает IP адрес */
    private static final byte DHCP_OFFER = 6;
    /**  DHCP REQUEST - запрашивает конкретный IP-адрес */
    private static final byte DHCP_REQUEST = 7;
    /**  DHCP ACK - DHCP сервер подтверждает выделение адреса */
    private static final byte DHCP_ACK = 8;

    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10;


    private static final byte DNS_DISCOVER = 30;
    private static final byte DNS_ANNOUNCE = 31;
    private static final byte DNS_REGISTER = 32;
    private static final byte DNS_RESOLVE = 33;
    private static final byte DNS_RESPONSE = 34;

    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;
    private static final byte ARP_RESPONSE = 23;

    /** MAC адрес DNS сервера  */
    private static String SERVER_MAC = "AA:BB:CC:DD:EE:DD";
    /** IP адрес DNS-сервера (изначально не назначен) */
    private static String SERVER_IP = "0.0.0.0";

    /** Хранилище DNS (доменное имя - IP-адрес) */
    private static final Map<String, String> dnsRecords = new HashMap<>();
    /**
     * ARP таблица (IP-адрес - MAC-адрес)
     */
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());

    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;
    private static String ROUTER_ADDRESS = "127.0.0.1";
    private static int ROUTER_PORT = 8081;

    // Таймаут соединения в миллисекундах
    private static final int CONNECTION_TIMEOUT = 30000;
    /** Максимальное количество попыток переподключения */
    private static final int MAX_RECONNECT_ATTEMPTS = 5;
    /** Задержка между попытками переподключения в миллисекундах (2 секунды) */
    private static final int RECONNECT_DELAY = 2000;

    /** Флаг работы сервера */
    private volatile boolean running = true;
    /** Флаг назначения IP-адреса */
    private static volatile boolean ipAssigned = false;
    /** IP-адрес, предложенный DHCP-сервером */
    private volatile String dhcpOfferedIP = null;
    /** Список доступных IP-адресов от DHCP-сервера */
    private volatile List<String> availableIPs = new ArrayList<>();
    /** Флаг получения DHCP ACK */
    private volatile boolean dhcpAckReceived = false;
    private volatile CountDownLatch dhcpLatch = new CountDownLatch(1);
    /** MAC-адрес, полученный из ARP-ответа */
    private volatile String arpResponseMAC = null;
    /** Флаг активности соединения */
    private volatile boolean connectionActive = false;

    public static void main(String[] args) {
        // Создаем сканер для чтения пользовательского ввода
        Scanner scanner = new Scanner(System.in);

        System.out.println("DNS-сервер запускается...");

        // Запрашиваем MAC-адрес сервера или используем значение по умолчанию
        System.out.println("Введите MAC-адрес DNS-сервера (или нажмите Enter для " + SERVER_MAC + "):");
        String mac = scanner.nextLine();
        if (!mac.isEmpty()) {
            SERVER_MAC = mac; // Устанавливаем введенный MAC-адрес
        }

        // Запрашиваем адрес маршрутизатора или используем значение по умолчанию
        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для " + ROUTER_ADDRESS + "):");
        String routerAddress = scanner.nextLine();
        if (!routerAddress.isEmpty()) {
            ROUTER_ADDRESS = routerAddress; // Устанавливаем введенный адрес маршрутизатора
        }

        // Запрашиваем порт маршрутизатора или используем значение по умолчанию
        System.out.println("Введите порт маршрутизатора (или нажмите Enter для " + ROUTER_PORT + "):");
        String portInput = scanner.nextLine();
        if (!portInput.isEmpty()) {
            try {
                ROUTER_PORT = Integer.parseInt(portInput); // Преобразуем строку в число и устанавливаем порт
            } catch (NumberFormatException e) {
                System.out.println("Неверный формат порта, используется порт " + ROUTER_PORT);
            }
        }

        // Запрашиваем IP-адрес или устанавливаем получение через DHCP
        System.out.println("Введите IP-адрес DNS-сервера (или нажмите Enter для получения через DHCP):");
        String ip = scanner.nextLine();
        if (!ip.isEmpty()) {
            SERVER_IP = ip; // Устанавливаем введенный IP-адрес
            ipAssigned = true; // Отмечаем, что IP уже назначен
        }

        // Создаем экземпляр DNS-сервера и запускаем его
        DNSServer dnsServer = new DNSServer();
        dnsServer.start(scanner);
    }


    public void start(Scanner scanner) {
        try {
            // Подключаемся к маршрутизатору
            connectToRouter();

            // Запускаем поток мониторинга соединения
            Thread monitorThread = new Thread(this::monitorConnection);
            monitorThread.setDaemon(true); // Устанавливаем поток как демон (завершится вместе с главным потоком)
            monitorThread.start();

            // Запускаем поток для прослушивания входящих сообщений
            Thread listenThread = new Thread(this::listenForMessages);
            listenThread.setDaemon(true); // Устанавливаем поток как демон
            listenThread.start();

            // Если IP не был указан, получаем его через DHCP
            if (!ipAssigned) {
                System.out.println("Попытка получения IP через DHCP...");
                performDhcpProcess(scanner);

                if (!ipAssigned) {
                    // Если DHCP не сработал, предложим установить IP вручную
                    System.out.println("Не удалось получить IP через DHCP.");
                    System.out.print("Хотите установить статический IP? (да/нет): ");
                    String response = scanner.nextLine().toLowerCase();
                    if (response.equals("да") || response.equals("yes") || response.equals("y")) {
                        System.out.print("Введите IP-адрес: ");
                        SERVER_IP = scanner.nextLine();
                        ipAssigned = true;
                    } else {
                        System.out.println("Выход.");
                        running = false;
                        closeConnection();
                        return;
                    }
                }
            }

            System.out.println("DNS-сервер успешно запущен с IP: " + SERVER_IP);

            // Отправляем широковещательное объявление о DNS сервере
            sendDnsAnnouncement();

            // меню
            while (running) {
                System.out.println("\nМеню DNS-сервера:");
                System.out.println("1. Показать все DNS-записи");
                System.out.println("2. Добавить DNS-запись вручную");
                System.out.println("3. Удалить DNS-запись");
                System.out.println("4. Отправить объявление о DNS-сервере");
                System.out.println("5. Проверить соединение");
                System.out.println("6. Переподключиться к маршрутизатору");
                System.out.println("7. Выход");
                System.out.print("Выберите действие: ");

                String choice = scanner.nextLine();

                // Обрабатываем выбор пользователя
                switch (choice) {
                    case "1":
                        showDnsRecords(); // Показываем все DNS-записи
                        break;
                    case "2":
                        addDnsRecord(scanner); // Добавляем DNS-запись
                        break;
                    case "3":
                        removeDnsRecord(scanner); // Удаляем DNS-запись
                        break;
                    case "4":
                        sendDnsAnnouncement(); // Отправляем объявление о DNS-сервере
                        break;
                    case "5":
                        checkConnection(); // Проверяем соединение с маршрутизатором
                        break;
                    case "6":
                        reconnectToRouter(); // Переподключаемся к маршрутизатору
                        break;
                    case "7":
                        running = false; // Завершаем работу
                        System.out.println("Завершение работы DNS-сервера...");
                        closeConnection();
                        break;
                    default:
                        System.out.println("Неверный выбор. Пожалуйста, попробуйте снова.");
                }
            }

        } catch (IOException e) {
            System.out.println("Ошибка соединения: " + e.getMessage());
        } finally {
            closeConnection();
        }
    }

    /**
     * Мониторит состояние соединения с маршрутизатором.
     * Периодически проверяет соединение и пытается переподключиться при необходимости.
     */
    private void monitorConnection() {
        while (running) {
            try {
                // Проверяем, активно ли соединение
                if (socket == null || socket.isClosed() || !connectionActive) {
                    System.out.println("Соединение неактивно. Попытка переподключения...");
                    reconnectToRouter(); // Пытаемся переподключиться
                }
                Thread.sleep(10000); // Проверяем каждые 10 секунд
            } catch (Exception e) {
                System.out.println("Ошибка мониторинга соединения: " + e.getMessage());
            }
        }
    }

    /**
     * Проверяет состояние соединения с маршрутизатором и выводит сообщение.
     */
    private void checkConnection() {
        if (socket != null && !socket.isClosed() && connectionActive) {
            System.out.println("Соединение активно");
        } else {
            System.out.println("Соединение неактивно");
        }
    }

    /**
     * Устанавливает соединение с маршрутизатором.
     * Создает сокет и потоки ввода/вывода.
     *
     * @throws IOException Если произошла ошибка при соединении
     */
    private synchronized void connectToRouter() throws IOException {
        closeConnection(); // Закрываем предыдущее соединение, если оно существует

        System.out.println("Подключение к маршрутизатору " + ROUTER_ADDRESS + ":" + ROUTER_PORT);
        socket = new Socket();
        socket.setSoTimeout(CONNECTION_TIMEOUT); // Устанавливаем таймаут чтения
        socket.connect(new InetSocketAddress(ROUTER_ADDRESS, ROUTER_PORT), CONNECTION_TIMEOUT); // Подключаемся с таймаутом
        outputStream = socket.getOutputStream(); // Получаем поток для отправки данных
        inputStream = socket.getInputStream(); // Получаем поток для чтения данных
        connectionActive = true; // Отмечаем соединение как активное
        System.out.println("Подключение к маршрутизатору установлено");
    }

    /**
     * Закрывает соединение с маршрутизатором.
     * Освобождает все ресурсы (сокет и потоки ввода/вывода).
     */
    private synchronized void closeConnection() {
        connectionActive = false; // Помечаем соединение как неактивное
        try {
            // Закрываем ресурсы если они существуют
            if (outputStream != null) outputStream.close();
            if (inputStream != null) inputStream.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            System.out.println("Ошибка при закрытии соединения: " + e.getMessage());
        } finally {
            // Обнуляем все ресурсы
            outputStream = null;
            inputStream = null;
            socket = null;
        }
    }

    /**
     * Пытается переподключиться к маршрутизатору.
     * Делает несколько попыток с задержкой между ними.
     *
     * @return true, если переподключение успешно, иначе false
     */
    private synchronized boolean reconnectToRouter() {
        int attempts = 0;
        while (attempts < MAX_RECONNECT_ATTEMPTS && running) {
            try {
                System.out.println("Попытка переподключения к маршрутизатору #" + (attempts + 1));
                connectToRouter(); // Пытаемся подключиться
                System.out.println("Переподключение успешно");
                return true;
            } catch (IOException e) {
                System.out.println("Ошибка переподключения: " + e.getMessage());
                attempts++;
                try {
                    Thread.sleep(RECONNECT_DELAY); // Ждем перед следующей попыткой
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        System.out.println("Не удалось переподключиться после " + MAX_RECONNECT_ATTEMPTS + " попыток");
        return false;
    }

    /**
     * Выполняет процесс получения IP-адреса через DHCP.
     * Отправляет DHCP-запросы и обрабатывает ответы.
     */
    private void performDhcpProcess(Scanner scanner) {
        try {
            // Отправляем DHCP Discover
            System.out.println("Отправка DHCP Discover...");
            // Отправляем широковещательное сообщение всем устройствам в сети
            sendMessage("FF:FF:FF:FF:FF:FF", SERVER_MAC, DHCP_DISCOVER, "255.255.255.255", "0.0.0.0", "");

            // Ждем получения информации от сервера
            Thread.sleep(5000); // Увеличиваем таймаут до 5 секунд

            // Выбираем IP-адрес
            String requestedIP = null;

            if (dhcpOfferedIP != null) {
                // Если получили предложение IP через DHCP Offer, используем его
                requestedIP = dhcpOfferedIP;
                System.out.println("Используем предложенный IP: " + requestedIP);
            } else if (!availableIPs.isEmpty()) {
                // Если получили список доступных IP, но не получили DHCP Offer
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
                System.out.println("Не получен ни DHCP Offer, ни список доступных IP, процесс не завершен");
                return;
            }

            // Отправляем DHCP Request
            System.out.println("Отправка DHCP Request для IP: " + requestedIP);
            sendMessage("FF:FF:FF:FF:FF:FF", SERVER_MAC, DHCP_REQUEST, "255.255.255.255", "0.0.0.0", requestedIP);

            // Ждем DHCP ACK
            Thread.sleep(5000);

            if (dhcpAckReceived) {
                SERVER_IP = requestedIP; // Устанавливаем полученный IP
                ipAssigned = true; // Отмечаем, что IP назначен
                System.out.println("DHCP процесс завершен успешно, получен IP: " + SERVER_IP);
            } else {
                System.out.println("Не получен DHCP ACK, процесс не завершен");
            }

        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Отправляет широковещательное объявление о DNS-сервере.
     * Сообщает другим устройствам в сети о наличии DNS-сервера.
     */
    private void sendDnsAnnouncement() {
        if (!ipAssigned) {
            System.out.println("IP-адрес не назначен, объявление не отправлено");
            return;
        }

        System.out.println("Отправка объявления о DNS-сервере...");
        sendMessage("FF:FF:FF:FF:FF:FF", SERVER_MAC, DNS_ANNOUNCE, "255.255.255.255", SERVER_IP, "DNS_SERVER_ANNOUNCE");

        // Повторяем отправку через некоторое время для надежности
        new Thread(() -> {
            try {
                Thread.sleep(1000);
                sendMessage("FF:FF:FF:FF:FF:FF", SERVER_MAC, DNS_ANNOUNCE, "255.255.255.255", SERVER_IP, "DNS_SERVER_ANNOUNCE");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }).start();
    }

    /**
     * Отображает все текущие DNS-записи.
     */
    private void showDnsRecords() {
        System.out.println("\nТекущие DNS-записи:");
        if (dnsRecords.isEmpty()) {
            System.out.println("DNS-записей нет");
        } else {
            int i = 1;
            for (Map.Entry<String, String> entry : dnsRecords.entrySet()) {
                System.out.println(i++ + ". " + entry.getKey() + " -> " + entry.getValue());
            }
        }
    }

    /**
     * Добавляет новую DNS-запись.
     * Запрашивает у пользователя доменное имя и IP-адрес.
     */
    private void addDnsRecord(Scanner scanner) {
        System.out.print("Введите доменное имя: ");
        String domain = scanner.nextLine().trim().toLowerCase(); // Приводим к нижнему регистру для единообразия

        System.out.print("Введите IP-адрес: ");
        String ip = scanner.nextLine().trim();

        if (domain.isEmpty() || ip.isEmpty()) {
            System.out.println("Доменное имя и IP не могут быть пустыми");
            return;
        }

        // Проверка формата IP
        if (!isValidIpAddress(ip)) {
            System.out.println("Неверный формат IP-адреса");
            return;
        }

        // Проверяем конфликты - один IP не может быть назначен разным доменам
        for (Map.Entry<String, String> entry : dnsRecords.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(domain) && entry.getValue().equals(ip)) {
                System.out.println("Ошибка: IP " + ip + " уже используется доменом " + entry.getKey());
                return;
            }
        }

        dnsRecords.put(domain, ip); // Добавляем запись в таблицу
        System.out.println("DNS-запись добавлена: " + domain + " -> " + ip);
    }

    /**
     * Удаляет DNS запись по доменному имени.
     */
    private void removeDnsRecord(Scanner scanner) {
        if (dnsRecords.isEmpty()) {
            System.out.println("DNS-записей нет");
            return;
        }

        showDnsRecords(); // Показываем текущие записи
        System.out.print("Введите доменное имя для удаления: ");
        String domain = scanner.nextLine().trim().toLowerCase(); // Приводим к нижнему регистру

        if (dnsRecords.remove(domain) != null) {
            System.out.println("DNS-запись для " + domain + " удалена");
        } else {
            System.out.println("DNS-запись для " + domain + " не найдена");
        }
    }

    /**
     * Проверяет, является ли строка корректным IP-адресом.
     *
     * @param ip Строка, содержащая предполагаемый IP-адрес
     * @return true, если IP-адрес корректен, иначе false
     */
    private boolean isValidIpAddress(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false; // IP должен состоять из 4 частей
            }

            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false; // Каждая часть должна быть числом от 0 до 255
                }
            }

            return true;
        } catch (NumberFormatException e) {
            return false; // Если не удалось преобразовать часть в число
        }
    }

    /**
     * Получает MAC-адрес для указанного IP-адреса.
     * Если MAC-адрес отсутствует в ARP-таблице, отправляет ARP-запрос.
     *
     * @param ip IP-адрес, для которого нужно получить MAC-адрес
     * @return MAC-адрес или null, если его не удалось получить
     */
    private String getMacAddress(String ip) {
        if (tableARP.containsKey(ip)) {
            return tableARP.get(ip); // Возвращаем MAC из таблицы, если он уже известен
        } else {
            // Отправляем ARP запрос
            sendMessage("FF:FF:FF:FF:FF:FF", SERVER_MAC, ARP_REQUEST, ip, SERVER_IP, "");

            // Ждем пока придёт ARP response
            try {
                int tries = 0; // количество попыток
                while (arpResponseMAC == null && tries < 10) {
                    Thread.sleep(200); // Ждем 200 мс
                    tries++;
                }
                if (arpResponseMAC != null) {
                    String mac = arpResponseMAC;
                    arpResponseMAC = null; // сбрасываем для следующего запроса
                    tableARP.put(ip, mac); // Добавляем полученный MAC в таблицу
                    return mac;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * Прослушивает входящие сообщения и обрабатывает их.
     * Запускается в отдельном потоке.
     */
    private void listenForMessages() {
        while (running) {
            try {
                if (socket == null || socket.isClosed() || !connectionActive) {
                    Thread.sleep(1000);
                    continue;
                }

                // Читаем пакет
                byte[] destMacBuffer = new byte[MAC_SIZE];
                int bytesRead = inputStream.read(destMacBuffer);
                if (bytesRead != MAC_SIZE) {
                    if (bytesRead == -1) {
                        System.out.println("Соединение закрыто сервером");
                        connectionActive = false;
                        continue; // Не выходим из цикла, будем переподключаться
                    }
                    continue;
                }

                // Читаем MAC-адрес источника
                byte[] srcMacBuffer = new byte[MAC_SIZE];
                bytesRead = inputStream.read(srcMacBuffer);
                if (bytesRead != MAC_SIZE) continue;

                // Читаем тип запроса
                byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
                bytesRead = inputStream.read(reqTypeBuffer);
                if (bytesRead != REQUEST_TYPE_SIZE) continue;

                // Читаем IP-адрес назначения
                byte[] destIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(destIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                // Читаем IP-адрес источника
                byte[] srcIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(srcIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                // Чтение длины данных (4 байта)
                byte[] dataLengthBuffer = new byte[4];
                bytesRead = inputStream.read(dataLengthBuffer);
                if (bytesRead != 4) continue;

                // Преобразуем длину данных из байтов в число
                int dataLength = byteArrayToInt(dataLengthBuffer);
                if (dataLength > MAX_DATA_SIZE || dataLength < 0) {
                    dataLength = MAX_DATA_SIZE; // Ограничиваем размер
                }

                // Читаем данные
                byte[] dataBuffer = new byte[dataLength];
                bytesRead = inputStream.read(dataBuffer);
                if (bytesRead != dataLength) continue;

                // Преобразуем в строки
                String destMac = new String(destMacBuffer).trim();
                String srcMac = new String(srcMacBuffer).trim();
                byte requestType = reqTypeBuffer[0];
                String destIp = new String(destIpBuffer).trim();
                String srcIp = new String(srcIpBuffer).trim();
                String data = new String(dataBuffer).trim();

                // Сохраняем MAC адрес источника в ARP таблицу (для всех не broadcast пакетов)
                if (!srcMac.equals("FF:FF:FF:FF:FF:FF") && !srcIp.equals("0.0.0.0")) {
                    tableARP.put(srcIp, srcMac);
                }

                // Проверяем, что пакет предназначен для нас или широковещательный
                boolean isForUs = destMac.equals(SERVER_MAC) ||
                        destMac.equals("FF:FF:FF:FF:FF:FF") ||
                        (destIp.equals(SERVER_IP) && !SERVER_IP.equals("0.0.0.0")) ||
                        destIp.equals("255.255.255.255");

                if (!isForUs) {
                    continue; // Пакет не для нас
                }

                // Выводим информацию о полученном пакете
                String requestTypeStr = getRequestTypeName(requestType);
                System.out.println(String.format(
                        "DNS-сервер получил пакет -> DestMAC:%s, SrcMAC:%s, Type:%s, DestIP:%s, SrcIP:%s, Data:%s",
                        destMac, srcMac, requestTypeStr, destIp, srcIp, data
                ));

                // Обрабатываем пакет
                handleIncomingMessage(destMac, srcMac, requestType, destIp, srcIp, data);

            } catch (SocketTimeoutException e) {
                //продолжаем слушать
            } catch (SocketException e) {
                System.out.println("Ошибка сокета: " + e.getMessage());
                connectionActive = false; // Помечаем соединение как неактивное
                try {
                    Thread.sleep(1000); // Ждем перед следующей итерацией
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            } catch (IOException e) {
                System.out.println("Ошибка ввода/вывода: " + e.getMessage());
                connectionActive = false; // Помечаем соединение как неактивное
            } catch (Exception e) {
                System.out.println("Неожиданная ошибка: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    /**
     * Обрабатывает входящее сообщение в зависимости от его типа.
     *
     * @param destinationMAC MAC-адрес назначения
     * @param sourceMAC MAC-адрес источника
     * @param requestType Тип запроса
     * @param destinationIP IP-адрес назначения
     * @param sourceIP IP-адрес источника
     * @param data Данные сообщения
     */
    private void handleIncomingMessage(String destinationMAC, String sourceMAC, byte requestType,
                                       String destinationIP, String sourceIP, String data) {
        try {
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
                case DNS_DISCOVER:
                    handleDnsDiscover(sourceMAC, sourceIP); // Обработка запроса на обнаружение DNS-сервера
                    break;
                case DNS_REGISTER:
                    handleDnsRegister(data, sourceMAC, sourceIP); // Обработка запроса на регистрацию домена
                    break;
                case DNS_RESOLVE:
                    handleDnsResolve(data, sourceMAC, sourceIP); // Обработка запроса на разрешение имени
                    break;
                case ARP_REQUEST:
                    // Отвечаем на ARP запрос, если он для нашего IP
                    if (destinationIP.equals(SERVER_IP)) {
                        System.out.println("Получен ARP запрос от " + sourceIP + ", отправляем ответ...");
                        sendMessage(sourceMAC, SERVER_MAC, ARP_RESPONSE, sourceIP, SERVER_IP, SERVER_MAC);
                    }
                    break;
                case ARP_RESPONSE:
                    // Получаем MAC из ответа
                    if (destinationMAC.equals(SERVER_MAC)) {
                        arpResponseMAC = data.isEmpty() ? sourceMAC : data;
                        System.out.println("Получен ARP ответ от " + sourceIP + " с MAC: " + arpResponseMAC);
                    }
                    break;
            }
        } catch (Exception e) {
            System.out.println("Ошибка при обработке сообщения: " + e.getMessage());
        }
    }

    /**
     * Обрабатывает запрос на обнаружение DNS-сервера.
     * Отвечает клиенту, сообщая о себе.
     *
     * @param clientMac MAC-адрес клиента
     * @param clientIp IP-адрес клиента
     */
    private void handleDnsDiscover(String clientMac, String clientIp) {
        System.out.println("Получен запрос на обнаружение DNS-сервера от " + clientIp);
        // Добавляем небольшую задержку перед ответом для повышения надежности
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // Отправляем клиенту объявление о DNS-сервере
        sendMessage(clientMac, SERVER_MAC, DNS_ANNOUNCE, clientIp, SERVER_IP, "DNS_SERVER_ANNOUNCE");
    }

    /**
     * Обрабатывает запрос на регистрацию доменного имени.
     * Проверяет корректность запроса и добавляет запись в таблицу.
     *
     * @param data Данные запроса
     * @param clientMac MAC-адрес клиента
     * @param clientIp IP-адрес клиента
     */
    private void handleDnsRegister(String data, String clientMac, String clientIp) {
        System.out.println("Получен запрос на регистрацию домена: " + data);

        // Парсим сообщение DNS REGISTER
        String[] parts = data.split("\\s+");
        if (parts.length < 4) {
            // Недостаточно аргументов
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS REGISTER ERROR Not enough arguments");
            return;
        }

        if (!parts[0].equalsIgnoreCase("DNS") || !parts[1].equalsIgnoreCase("REGISTER")) {
            // Неверный формат команды
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS REGISTER ERROR Invalid command format");
            return;
        }

        String domainToReg = parts[2].toLowerCase(); // Приводим домен к нижнему регистру
        String ipToReg = parts[3];

        // Проверяем, что IP валидный
        if (!isValidIpAddress(ipToReg)) {
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS REGISTER ERROR Invalid IP format");
            return;
        }

        // Проверяем конфликты - один IP не может быть назначен разным доменам
        for (Map.Entry<String, String> entry : dnsRecords.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(domainToReg) && entry.getValue().equals(ipToReg)) {
                String errorMsg = "DNS REGISTER ERROR: IP " + ipToReg + " уже используется доменом " + entry.getKey();
                sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP, errorMsg);
                return;
            }
        }

        // Добавляем запись
        dnsRecords.put(domainToReg, ipToReg);
        System.out.println("Добавлена DNS-запись: " + domainToReg + " -> " + ipToReg);

        // Добавляем задержку перед отправкой ответа для надёжности
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Отправляем подтверждение
        sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                "DNS REGISTER OK " + domainToReg + " " + ipToReg);
    }

    /**
     * Обрабатывает запрос на разрешение доменного имени в IP-адрес.
     *
     * @param data Данные запроса (строка формата "DNS RESOLVE domain")
     * @param clientMac MAC-адрес клиента
     * @param clientIp IP-адрес клиента
     */
    private void handleDnsResolve(String data, String clientMac, String clientIp) {
        System.out.println("Получен запрос на разрешение имени: " + data);

        // Парсим сообщение DNS RESOLVE
        String[] parts = data.split("\\s+");
        if (parts.length < 3) {
            // Домен не указан
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS RESOLVE ERROR No domain specified");
            return;
        }

        if (!parts[0].equalsIgnoreCase("DNS") || !parts[1].equalsIgnoreCase("RESOLVE")) {
            // Неверный формат команды
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS RESOLVE ERROR Invalid command format");
            return;
        }

        String domainToResolve = parts[2].toLowerCase(); // Приводим домен к нижнему регистру
        String ipFound = dnsRecords.get(domainToResolve); // Ищем IP для домена

        // Добавляем задержку перед отправкой ответа для надёжности
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        if (ipFound != null) {
            // Домен найден, отправляем IP
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS RESOLVE OK " + domainToResolve + " " + ipFound);
        } else {
            // Домен не найден
            sendMessage(clientMac, SERVER_MAC, DNS_RESPONSE, clientIp, SERVER_IP,
                    "DNS RESOLVE NOTFOUND " + domainToResolve);
        }
    }

    /**
     * Отправляет сетевое сообщение.
     *
     * @param destMAC MAC-адрес получателя
     * @param srcMAC MAC-адрес отправителя
     * @param reqType Тип запроса
     * @param destIP IP-адрес получателя
     * @param srcIP IP-адрес отправителя
     * @param data Данные сообщения
     */
    private synchronized void sendMessage(String destMAC, String srcMAC, byte reqType,
                                          String destIP, String srcIP, String data) {
        if (!connectionActive || socket == null || socket.isClosed()) {
            System.out.println("Соединение неактивно, невозможно отправить сообщение");
            return;
        }

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

            // Записываем все поля последовательно в поток
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush(); // Сбрасываем буфер

            // Выводим отладочную информацию
            String requestTypeStr = getRequestTypeName(reqType);
            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destMAC +
                    " (IP: " + destIP + "), данные: " + data);

        } catch (IOException e) {
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());
            connectionActive = false; // Помечаем соединение как неактивное
        }
    }

    /**
     * Получает строковое представление типа запроса по его коду.
     */
    private String getRequestTypeName(byte requestType) {
        switch (requestType) {
            case DHCP_DISCOVER: return "DHCP_DISCOVER";
            case DHCP_OFFER: return "DHCP_OFFER";
            case DHCP_REQUEST: return "DHCP_REQUEST";
            case DHCP_ACK: return "DHCP_ACK";
            case ERROR: return "ERROR";
            case DHCP_AVAILABLE_IPS: return "DHCP_AVAILABLE_IPS";
            case DNS_DISCOVER: return "DNS_DISCOVER";
            case DNS_ANNOUNCE: return "DNS_ANNOUNCE";
            case DNS_REGISTER: return "DNS_REGISTER";
            case DNS_RESOLVE: return "DNS_RESOLVE";
            case DNS_RESPONSE: return "DNS_RESPONSE";
            case PING: return "PING";
            case PONG: return "PONG";
            case ARP_REQUEST: return "ARP_REQUEST";
            case ARP_RESPONSE: return "ARP_RESPONSE";
            default: return "UNKNOWN(" + requestType + ")";
        }
    }

    /**
     * Преобразует массив байтов в целое число (int).
     *
     * @param bytes Массив из 4 байтов
     * @return Целое число
     */
    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    /**
     * Преобразует целое число (int) в массив из 4 байтов.
     *
     * @param value Целое число
     * @return Массив из 4 байтов
     */
    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),  // Старший байт
                (byte)(value >>> 16),  // 2-й байт
                (byte)(value >>> 8),   // 3-й байт
                (byte)value            // Младший байт
        };
    }

    /**
     * Дополняет строку пробелами справа до указанной длины.
     * Обрезает строку, если она длиннее указанной длины.
     *
     * @param s Исходная строка
     * @param n Требуемая длина
     * @return Строка дополненная пробелами или обрезанная до указанной длины
     */
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n); // Обрезаем до нужной длины
        }
        return String.format("%-" + n + "s", s); // Дополняем пробелами справа
    }
}