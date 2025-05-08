import java.io.*;      // Импорт классов для ввода/вывода
import java.net.*;     // Импорт классов для работы с сетью
import java.util.Collections;  // Импорт для создания синхронизированных коллекций
import java.util.HashMap;      // Импорт для работы с хеш-таблицами
import java.util.Map;          // Импорт интерфейса Map
import java.util.Scanner;      // Импорт для работы с пользовательским вводом
import java.util.concurrent.ConcurrentHashMap; // Импорт для потокобезопасной хеш-таблицы
import java.util.Random;       // Импорт для генерации случайных чисел

public class NATRouter {
    private static String ROUTER_MAC = "AA:BB:CC:DD:EE:FF";
    private static String ROUTER_IP = "192.168.1.1";
    /** Публичный IP-адрес маршрутизатора для внешней сети */
    private static String PUBLIC_IP = "203.0.113.1";
    /** Префикс локальной сети для определения принадлежности IP-адресов */
    private static final String LOCAL_NETWORK_PREFIX = "192.168.1.";
    /** Префикс внешней сети для определения принадлежности IP-адресов */
    private static final String EXTERNAL_NETWORK_PREFIX = "203.0.113.";

    /** IP-адрес DHCP-сервера и порт*/
    private static String dhcpServerAddress;
    private static int dhcpServerPort;

    /**
     * MAC - сокет
     */
    private static final Map<String, Socket> tableCAM = Collections.synchronizedMap(new HashMap<>());

    /**
     * ARP таблица
     */
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());

    /**
     * NAT таблица локальный_IP порт - внешний порт на маршрутизаторе.
     * Используется для трансляции исходящих пакетов.
     */
    private static final Map<String, Integer> natTable = new ConcurrentHashMap<>();

    /**
     * Обратная NAT таблица соответствие порта на маршрутизаторе - локальный_IP порт.
     */
    private static final Map<Integer, String> reverseNatTable = new ConcurrentHashMap<>();

    /** Начальный порт для NAT*/
    private static int nextNatPort = 10000;
    /** Генератор случайных чисел для портов NAT */
    private static final Random random = new Random();

    /**  DHCP DISCOVER - клиент запрашивает IP-адрес */
    private static final byte DHCP_DISCOVER = 5;
    /**  DHCP OFFER - сервер предлагает IP-адрес */
    private static final byte DHCP_OFFER = 6;
    /**  DHCP REQUEST - клиент запрашивает конкретный IP-адрес */
    private static final byte DHCP_REQUEST = 7;
    /** DHCP ACK - сервер подтверждает выделение IP-адреса */
    private static final byte DHCP_ACK = 8;
    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10;

    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;
    private static final byte ARP_RESPONSE = 23;

    /** DNS DISCOVER - запрос на обнаружение DNS-сервера */
    private static final byte DNS_DISCOVER = 30;
    /**  DNS ANNOUNCE - объявление DNS-сервера */
    private static final byte DNS_ANNOUNCE = 31;
    /** DNS REGISTER - запрос на регистрацию домена */
    private static final byte DNS_REGISTER = 32;
    /** DNS RESOLVE - запрос на разрешение имени в IP */
    private static final byte DNS_RESOLVE = 33;
    /** DNS RESPONSE - ответ DNS-сервера */
    private static final byte DNS_RESPONSE = 34;

    /** HTTP GET - запрос HTTP-страницы */
    private static final byte HTTP_GET = 40;
    /** HTTP RESPONSE - ответ с HTTP-страницей */
    private static final byte HTTP_RESPONSE = 41;

    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Запрашиваем IP-адрес в локальной сети
        System.out.println("Введите IP маршрутизатора в локальной сети (или нажмите Enter для 192.168.1.1):");
        String input = scanner.nextLine();
        if (!input.isEmpty()) {
            ROUTER_IP = input;
        }

        // Запрашиваем публичный IP-адрес
        System.out.println("Введите публичный IP маршрутизатора (или нажмите Enter для 203.0.113.1):");
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            PUBLIC_IP = input; // Устанавливаем введенный публичный IP-адрес
        }

        // Запрашиваем MAC-адрес маршрутизатора
        System.out.println("Введите MAC маршрутизатора (или нажмите Enter для AA:BB:CC:DD:EE:FF):");
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            ROUTER_MAC = input; // Устанавливаем введенный MAC-адрес
        }

        // Запрашиваем порт маршрутизатора
        System.out.println("Введите порт для маршрутизатора (или нажмите Enter для 8081):");
        int port = 8081; // Порт по умолчанию
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            try {
                port = Integer.parseInt(input); // Преобразуем строку в число и устанавливаем порт
            } catch (NumberFormatException e) {
                // Обрабатываем ошибку, если введён некорректный порт
                System.out.println("Неверный формат порта, используется порт 8081");
            }
        }

        // Запрашиваем адрес DHCP-сервера
        System.out.println("Введите адрес DHCP-сервера (или нажмите Enter для 127.0.0.1):");
        dhcpServerAddress = "127.0.0.1";
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            dhcpServerAddress = input; // Устанавливаем введенный адрес DHCP-сервера
        }

        // Запрашиваем порт DHCP-сервера
        System.out.println("Введите порт DHCP-сервера (или нажмите Enter для 8080):");
        dhcpServerPort = 8080; // Порт по умолчанию
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            try {
                dhcpServerPort = Integer.parseInt(input); // Преобразуем строку в число и устанавливаем порт
            } catch (NumberFormatException e) {
                System.out.println("Неверный формат порта DHCP, используется порт 8080");
            }
        }

        // Добавляем маршрутизатор в ARP таблицу
        tableARP.put(ROUTER_IP, ROUTER_MAC);
        tableARP.put(PUBLIC_IP, ROUTER_MAC);

        System.out.println("Запуск NAT-маршрутизатора на порту " + port);
        System.out.println("IP в локальной сети: " + ROUTER_IP);
        System.out.println("Публичный IP: " + PUBLIC_IP);
        System.out.println("DHCP-сервер: " + dhcpServerAddress + ":" + dhcpServerPort);

        // Создаем сокет и начинаем прослушивать порт
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("NAT-маршрутизатор запущен и слушает порт " + port);

            // Запускаем поток для периодической очистки NAT-таблицы
            startNatTableCleanupThread();

            // Бесконечный цикл приема новых соединений
            while (true) {
                Socket clientSocket = serverSocket.accept(); // Блокирующий вызов - ждем подключения клиента
                new Thread(new ClientHandler(clientSocket)).start(); // Создаем новый поток для обработки клиента
            }
        } catch (IOException e) {
            System.err.println("Ошибка запуска: " + e.getMessage());
        }
    }

    /**
     * Запускает поток для периодической очистки устаревших записей в NAT-таблице.
     */
    private static void startNatTableCleanupThread() {
        Thread cleanupThread = new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(300000); // Очистка каждые 5 минут
                    // Логика очистки устаревших записей
                    System.out.println("Выполнена очистка NAT-таблицы. Текущее количество записей: " + natTable.size());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    /**
     * Проверяет, принадлежит ли IP-адрес локальной сети.
     *
     * @param ip IP-адрес для проверки
     * @return true, если адрес принадлежит локальной сети, иначе false
     */
    private static boolean isLocalIp(String ip) {
        return ip.startsWith(LOCAL_NETWORK_PREFIX) || ip.equals(ROUTER_IP) || ip.equals("127.0.0.1");
    }

    /**
     * Проверяет, принадлежит ли IP-адрес внешней сети.
     *
     * @param ip IP-адрес для проверки
     * @return true, если адрес принадлежит внешней сети, иначе false
     */
    private static boolean isExternalIp(String ip) {
        return !isLocalIp(ip) && !ip.equals("255.255.255.255");
    }

    /**
     * Добавляет запись в NAT-таблицу.
     *
     * @param localIp IP-адрес клиента в локальной сети
     * @param localPort порт клиента в локальной сети
     * @return порт на маршрутизаторе для этого соединения
     */
    private static int addNatMapping(String localIp, int localPort) {
        String key = localIp + ":" + localPort;

        // Проверяем существующую запись
        if (natTable.containsKey(key)) {
            return natTable.get(key);
        }

        // Генерируем уникальный порт для NAT
        int natPort;
        do {
            natPort = nextNatPort++;
            if (nextNatPort > 65000) nextNatPort = 10000; // При достижении максимума сбрасываем
        } while (reverseNatTable.containsKey(natPort));

        // Добавляем записи в обе таблицы
        natTable.put(key, natPort);
        reverseNatTable.put(natPort, key);

        System.out.println("NAT: Создано отображение " + key + " -> " + PUBLIC_IP + ":" + natPort);
        return natPort;
    }

    /**
     * Получает информацию о локальном клиенте по порту NAT.
     *
     * @param natPort порт NAT на маршрутизаторе
     * @return строка формата "IP:порт" для локального клиента или null, если не найдено
     */
    private static String getNatMappingByPort(int natPort) {
        return reverseNatTable.get(natPort);
    }

    /**
     * Класс для обработки подключения отдельного клиента в отдельном потоке.
     * Обрабатывает входящие пакеты и перенаправляет их соответствующим получателям.
     */
    static class ClientHandler implements Runnable {
        /** Сокет для связи с клиентом */
        private final Socket clientSocket;
        /** MAC-адрес клиента, определяется при первом пакете */
        private String clientMAC;
        /** IP-адрес клиента, определяется при первом пакете */
        private String clientIP;
        /** Флаг, указывающий, является ли клиент внешним узлом */
        private boolean isExternal = false;

        /**
         * Создает новый обработчик клиента.
         *
         * @param clientSocket Сокет, через который осуществляется связь с клиентом
         */
        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                String remoteAddress = clientSocket.getInetAddress().getHostAddress();
                int remotePort = clientSocket.getPort();
                System.out.println("Подключение клиента с " + remoteAddress + ":" + remotePort);

                // Сохраняем соединение по порту до получения MAC-адреса
                synchronized (tableCAM) {
                    tableCAM.put("temp_" + remotePort, clientSocket);
                }

                // Получаем поток ввода для чтения данных от клиента
                InputStream inputStream = clientSocket.getInputStream();
                int bytesRead;

                // Цикл чтения пакетов от клиента
                while (true) {
                    // Читаем MAC-адрес назначения
                    byte[] destMacBuffer = new byte[MAC_SIZE];
                    bytesRead = inputStream.read(destMacBuffer);
                    if (bytesRead != MAC_SIZE) {
                        if (bytesRead == -1) break;
                        continue;
                    }

                    // Читаем MAC-адрес отправителя
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

                    // Читаем данные пакета
                    byte[] dataBuffer = new byte[dataLength];
                    bytesRead = inputStream.read(dataBuffer);
                    if (bytesRead != dataLength) continue;

                    // Преобразуем все в строки
                    String destinationMAC = new String(destMacBuffer).trim();
                    String sourceMAC = new String(srcMacBuffer).trim();
                    byte requestType = reqTypeBuffer[0]; // Используем байт как код типа запроса
                    String destinationIP = new String(destIpBuffer).trim();
                    String sourceIP = new String(srcIpBuffer).trim();
                    String data = new String(dataBuffer).trim();

                    // При первом получении пакета от клиента, запоминаем его MAC и IP
                    if (clientMAC == null) {
                        clientMAC = sourceMAC;
                        clientIP = sourceIP;
                        isExternal = isExternalIp(sourceIP);

                        // Удаляем временную запись и добавляем постоянную в таблицу
                        synchronized (tableCAM) {
                            tableCAM.remove("temp_" + remotePort);
                            tableCAM.put(sourceMAC, clientSocket);
                        }

                        // Добавляем запись в ARP таблицу
                        synchronized (tableARP) {
                            tableARP.put(sourceIP, sourceMAC);
                        }

                        System.out.println("Клиент идентифицирован: MAC=" + clientMAC +
                                ", IP=" + clientIP +
                                (isExternal ? " (внешний)" : " (локальный)"));
                    }

                    String requestTypeStr = getRequestTypeName(requestType);

                    System.out.println("Получен пакет: MAC получателя=" + destinationMAC +
                            ", MAC отправителя=" + sourceMAC +
                            ", Тип запроса=" + requestTypeStr +
                            ", IP получателя=" + destinationIP +
                            ", IP отправителя=" + sourceIP +
                            ", Данные=" + (data.length() > 50 ? data.substring(0, 50) + "..." : data));

                    // Обрабатываем пакет в зависимости от его типа
                    processPacket(requestType, destinationMAC, sourceMAC,
                            destinationIP, sourceIP, data, clientSocket, remotePort);
                }

            } catch (IOException e) {
                System.out.println("Клиент отключился: " + e.getMessage());
            } finally {
                removeFromTables(clientSocket, clientMAC, clientIP); // Удаляем клиента из таблиц
            }
        }
    }

    /**
     * Удаляет информацию об отключившемся клиенте из всех таблиц маршрутизатора.
     *
     * @param clientSocket Сокет отключившегося клиента
     * @param clientMAC MAC-адрес клиента (может быть null, если не был определен)
     * @param clientIP IP-адрес клиента (может быть null, если не был определен)
     */
    private static void removeFromTables(Socket clientSocket, String clientMAC, String clientIP) {
        // Удаляем из таблицы
        synchronized (tableCAM) {
            // Удаляем по MAC-адресу, если он известен
            if (clientMAC != null) {
                tableCAM.remove(clientMAC);
                System.out.println("Клиент " + clientMAC + " удален из CAM-таблицы.");
            } else {
                // Если MAC неизвестен, ищем и удаляем по сокету
                String removedKey = null;
                for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                    if (entry.getValue() == clientSocket) {
                        removedKey = entry.getKey();
                        break;
                    }
                }
                if (removedKey != null) {
                    tableCAM.remove(removedKey);
                    System.out.println("Клиент с неизвестным MAC удален из CAM-таблицы.");
                }
            }
        }

        // Удаляем из ARP-таблицы
        if (clientIP != null && clientMAC != null) {
            synchronized (tableARP) {
                if (tableARP.get(clientIP) != null && tableARP.get(clientIP).equals(clientMAC)) {
                    tableARP.remove(clientIP);
                    System.out.println("Клиент с IP " + clientIP + " удален из ARP-таблицы.");
                }
            }
        }

        // Удаляем из NAT-таблицы
        if (clientIP != null) {
            // Находим все записи с этим IP в NAT-таблице
            natTable.entrySet().removeIf(entry -> {
                String key = entry.getKey();
                if (key.startsWith(clientIP + ":")) {
                    int port = entry.getValue();
                    reverseNatTable.remove(port);
                    System.out.println("NAT-запись для " + key + " удалена.");
                    return true;
                }
                return false;
            });
        }
    }

    /**
     * Обрабатывает пакет в зависимости от его типа.
     * Перенаправляет DHCP-запросы на DHCP-сервер, остальные пакеты - соответствующим получателям.
     * Реализует логику NAT для пакетов между локальной и внешней сетями.
     *
     * @param requestType    Тип запроса
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента-отправителя
     * @param sourcePort     Порт отправителя (для NAT)
     */
    private static void processPacket(
            byte requestType,
            String destinationMAC,
            String sourceMAC,
            String destinationIP,
            String sourceIP,
            String data,
            Socket clientSocket,
            int sourcePort
    ) {
        // Обработка DHCP-запросов
        if (requestType == DHCP_DISCOVER || requestType == DHCP_REQUEST) {
            forwardToDHCP(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
            return;
        }

        // Обработка ARP-запросов
        if (requestType == ARP_REQUEST) {
            handleArpRequest(destinationMAC, sourceMAC, destinationIP, sourceIP, clientSocket);
            return;
        }

        // Проверка, является ли пакет широковещательным
        if ("FF:FF:FF:FF:FF:FF".equalsIgnoreCase(destinationMAC)) {
            broadcastPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
            return;
        }

        // Определяем, принадлежат ли IP-адреса локальной или внешней сети
        boolean sourceIsLocal = isLocalIp(sourceIP);
        boolean destIsLocal = isLocalIp(destinationIP);

        // Если получатель - сам маршрутизатор
        if (destinationMAC.equals(ROUTER_MAC) ||
                destinationIP.equals(ROUTER_IP) ||
                destinationIP.equals(PUBLIC_IP)) {
            handleRouterPacket(requestType, sourceMAC, sourceIP, data, clientSocket);
            return;
        }

        // Выбираем стратегию маршрутизации на основе типа сетей
        if (sourceIsLocal && destIsLocal) {
            // Оба в локальной сети - простая пересылка
            forwardPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
        }
        else if (sourceIsLocal && !destIsLocal) {
            // Из локальной во внешнюю - применяем NAT
            forwardWithNat(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket, sourcePort);
        }
        else if (!sourceIsLocal && destIsLocal) {
            // Из внешней в локальную - применяем обратный NAT
            processIncomingExternalPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
        }
        else {
            // Оба во внешней сети - простая пересылка
            forwardPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
        }
    }

    /**
     * Обрабатывает ARP-запросы, учитывая NAT.
     * Особая обработка для запросов из локальной сети во внешнюю и наоборот.
     *
     * @param destinationMAC MAC-адрес назначения
     * @param sourceMAC      MAC-адрес отправителя
     * @param destinationIP  IP-адрес назначения (запрашиваемый)
     * @param sourceIP       IP-адрес отправителя
     * @param clientSocket   Сокет клиента-отправителя
     */
    private static void handleArpRequest(
            String destinationMAC,
            String sourceMAC,
            String destinationIP,
            String sourceIP,
            Socket clientSocket
    ) {
        System.out.println("Обработка ARP запроса от " + sourceIP + " для IP " + destinationIP);

        // Определяем принадлежность IP-адресов к сетям
        boolean sourceIsLocal = isLocalIp(sourceIP);
        boolean destIsLocal = isLocalIp(destinationIP);

        // Если IP принадлежит маршрутизатору, отвечаем его MAC-адресом
        if (destinationIP.equals(ROUTER_IP) || destinationIP.equals(PUBLIC_IP)) {
            sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ARP_RESPONSE, sourceIP, destinationIP, ROUTER_MAC);
            return;
        }

        // Если запрос из локальной сети во внешнюю
        if (sourceIsLocal && !destIsLocal) {
            // Отвечаем своим MAC-адресом для всех внешних IP-адресов
            sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ARP_RESPONSE, sourceIP, destinationIP, ROUTER_MAC);
            System.out.println("NAT: Ответ на ARP-запрос для внешнего IP " + destinationIP + " от " + sourceIP);
            return;
        }

        // Если запрос из внешней сети в локальную
        if (!sourceIsLocal && destIsLocal) {
            // Проверяем, есть ли MAC-адрес в ARP-таблице
            String targetMAC = tableARP.get(destinationIP);
            if (targetMAC != null) {
                // Отправляем запрошенный MAC-адрес
                sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ARP_RESPONSE, sourceIP, destinationIP, targetMAC);
                System.out.println("NAT: Ответ на ARP-запрос для внутреннего IP " + destinationIP + " от " + sourceIP);
            }
            return;
        }

        // Обычный ARP-запрос внутри одной сети
        String targetMAC = tableARP.get(destinationIP);
        if (targetMAC != null) {
            // Отправляем запрошенный MAC-адрес
            sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ARP_RESPONSE, sourceIP, destinationIP, targetMAC);
            System.out.println("Ответ на ARP-запрос для IP " + destinationIP + " от " + sourceIP);
        } else {
            // MAC-адрес не найден, широковещательный запрос всем клиентам
            broadcastPacket("FF:FF:FF:FF:FF:FF", sourceMAC, ARP_REQUEST, destinationIP, sourceIP, "", clientSocket);
        }
    }

    /**
     * Обрабатывает пакеты, адресованные самому маршрутизатору.
     *
     * @param requestType  Тип запроса
     * @param sourceMAC    MAC-адрес отправителя
     * @param sourceIP     IP-адрес отправителя
     * @param data         Данные пакета
     * @param clientSocket Сокет клиента-отправителя
     */
    private static void handleRouterPacket(
            byte requestType,
            String sourceMAC,
            String sourceIP,
            String data,
            Socket clientSocket
    ) {
        // Получаем строковое представление типа запроса
        String requestTypeStr = getRequestTypeName(requestType);
        System.out.println("Получен пакет для маршрутизатора типа " + requestTypeStr);

        // Обработка в зависимости от типа запроса
        switch (requestType) {
            case PING:
                // Отвечаем PONG на PING
                System.out.println("Отправка PONG в ответ на PING от " + sourceIP);
                sendPacket(clientSocket, sourceMAC, ROUTER_MAC, PONG, sourceIP, ROUTER_IP, "PONG от маршрутизатора");
                break;
            case ARP_REQUEST:
                // Отвечаем на ARP-запрос для маршрутизатора
                System.out.println("Отправка ARP_RESPONSE от маршрутизатора для " + sourceIP);
                sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ARP_RESPONSE, sourceIP, ROUTER_IP, ROUTER_MAC);
                break;
            default:
                System.out.println("Маршрутизатор получил запрос типа " + requestTypeStr + ", не требующий ответа");
                break;
        }
    }

    /**
     * Перенаправляет DHCP-запросы на DHCP-сервер и возвращает ответ клиенту.
     *
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента-отправителя
     */
    private static void forwardToDHCP(
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data,
            Socket clientSocket
    ) {
        try (Socket dhcpSocket = new Socket(dhcpServerAddress, dhcpServerPort)) {
            // Преобразуем тип запроса в строку
            String requestTypeStr = getRequestTypeName(requestType);

            System.out.println("Перенаправление DHCP пакета на сервер " + dhcpServerAddress + ":" + dhcpServerPort);

            // Отправляем пакет DHCP-серверу
            sendPacket(dhcpSocket, destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);

            // Ожидаем ответа от DHCP-сервера
            InputStream inputStream = dhcpSocket.getInputStream();

            // Читаем MAC-адрес назначения
            byte[] destMacBuffer = new byte[MAC_SIZE];
            inputStream.read(destMacBuffer);

            // Читаем MAC-адрес источника
            byte[] srcMacBuffer = new byte[MAC_SIZE];
            inputStream.read(srcMacBuffer);

            // Читаем тип запроса
            byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
            inputStream.read(reqTypeBuffer);

            // Читаем IP-адрес назначения
            byte[] destIpBuffer = new byte[IP_SIZE];
            inputStream.read(destIpBuffer);

            // Читаем IP-адрес источника
            byte[] srcIpBuffer = new byte[IP_SIZE];
            inputStream.read(srcIpBuffer);

            // Читаем длину данных
            byte[] dataLengthBuffer = new byte[4];
            inputStream.read(dataLengthBuffer);

            // Читаем данные ответа
            int responseDataLength = byteArrayToInt(dataLengthBuffer);
            byte[] responseDataBuffer = new byte[responseDataLength];
            inputStream.read(responseDataBuffer);

            // Преобразуем поля ответа в строки для логирования
            String responseDstMAC = new String(destMacBuffer).trim();
            String responseSrcMAC = new String(srcMacBuffer).trim();
            byte responseType = reqTypeBuffer[0];
            String responseDstIP = new String(destIpBuffer).trim();
            String responseSrcIP = new String(srcIpBuffer).trim();
            String responseData = new String(responseDataBuffer).trim();

            // Преобразуем тип ответа в строку
            String responseTypeStr = getRequestTypeName(responseType);

            System.out.println("Получен ответ от DHCP: " + responseTypeStr + ", пересылаем клиенту " + responseDstMAC);

            // Если это DHCP ACK, сохраняем выданный IP в ARP-таблицу
            if (responseType == DHCP_ACK && !responseData.isEmpty()) {
                tableARP.put(responseData, sourceMAC);
                System.out.println("DHCP: Добавлен IP " + responseData + " для MAC " + sourceMAC + " в ARP-таблицу");
            }

            // Перенаправляем ответ от DHCP-сервера клиенту
            sendPacket(clientSocket, responseDstMAC, responseSrcMAC, responseType,
                    responseDstIP, responseSrcIP, responseData);

        } catch (IOException e) {
            System.out.println("Ошибка подключения к DHCP-серверу: " + e.getMessage());
        }
    }

    /**
     * Перенаправляет пакет из локальной сети во внешнюю с применением NAT.
     *
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента-отправителя
     * @param sourcePort     Порт отправителя
     */
    private static void forwardWithNat(
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data,
            Socket clientSocket,
            int sourcePort
    ) {
        System.out.println("NAT: Исходящий пакет от " + sourceIP + " к " + destinationIP);

        int natPort = addNatMapping(sourceIP, sourcePort);

        // Получаем MAC-адрес получателя во внешней сети
        String destMAC = tableARP.get(destinationIP);
        if (destMAC == null) {
            // Если MAC неизвестен, для внешних адресов отвечаем MAC-адресом маршрутизатора
            System.out.println("NAT: Неизвестный MAC для IP " + destinationIP + ", используем собственный MAC для внешней сети");
            // Для внешних узлов всегда используем MAC маршрутизатора
            destMAC = ROUTER_MAC;
            tableARP.put(destinationIP, ROUTER_MAC);
        }

        // Получаем сокет получателя
        Socket destSocket = null;
        synchronized (tableCAM) {
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                String mac = entry.getKey();
                if (!mac.startsWith("temp_") && tableARP.containsValue(mac)) {
                    // Ищем для каждого MAC соответствующий IP
                    boolean foundMatch = false;
                    for (Map.Entry<String, String> arpEntry : tableARP.entrySet()) {
                        if (arpEntry.getValue().equals(mac) && arpEntry.getKey().equals(destinationIP)) {
                            foundMatch = true;
                            break;
                        }
                    }

                    if (foundMatch) {
                        destSocket = entry.getValue();
                        break;
                    }
                }
            }
        }

        if (destSocket == null || destSocket.isClosed()) {
            System.out.println("NAT: Не найден активный сокет для получателя " + destinationIP);
            sendPacket(clientSocket, sourceMAC, ROUTER_MAC, ERROR, sourceIP, ROUTER_IP,
                    "Не удалось найти получателя с IP " + destinationIP);
            return;
        }

        // Добавляем информацию о порте NAT
        String natInfo = "NAT_PORT=" + natPort + ";";
        String dataWithPort = natInfo + data;

        // Отправляем пакет с измененным IP-адресом источника
        sendPacket(destSocket, destMAC, ROUTER_MAC, requestType,
                destinationIP, PUBLIC_IP, dataWithPort);

        System.out.println("NAT: Пакет отправлен с заменой " + sourceIP + " -> " + PUBLIC_IP + " (порт: " + natPort + ")");
    }

    /**
     * Обрабатывает входящий пакет из внешней сети.
     * Восстанавливает исходный локальный IP-адрес получателя на основе NAT-таблицы.
     *
     * @param destinationMAC MAC-адрес получателя (маршрутизатора)
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя (публичный IP маршрутизатора)
     * @param sourceIP       IP-адрес отправителя (внешний)
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента-отправителя
     */
    private static void processIncomingExternalPacket(
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data,
            Socket clientSocket
    ) {
        System.out.println("NAT: Входящий пакет для " + destinationIP + " от " + sourceIP);

        // Извлекаем порт NAT
        int natPort = extractNatPortFromData(data);
        if (natPort == -1) {
            System.out.println("NAT: Не удалось извлечь порт NAT из пакета");
            return;
        }

        // Удаляем информацию о порте NAT
        String cleanData = removeNatInfoFromData(data);

        // Получаем информацию о локальном клиенте из NAT-таблицы
        String localMapping = getNatMappingByPort(natPort);
        if (localMapping == null) {
            System.out.println("NAT: Не найдено отображение для порта " + natPort);
            return;
        }

        // Разбиваем строку на IP и порт
        String[] parts = localMapping.split(":");
        String localIP = parts[0];

        // Получаем MAC-адрес и сокет локального получателя
        String localMAC = tableARP.get(localIP);
        if (localMAC == null) {
            System.out.println("NAT: Не найден MAC для IP " + localIP);
            return;
        }

        Socket localSocket = tableCAM.get(localMAC);
        if (localSocket == null || localSocket.isClosed()) {
            System.out.println("NAT: Не найден активный сокет для MAC " + localMAC);
            return;
        }

        // Отправляем пакет локальному клиенту
        sendPacket(localSocket, localMAC, ROUTER_MAC, requestType,
                localIP, sourceIP, cleanData);

        System.out.println("NAT: Входящий пакет перенаправлен с " +
                PUBLIC_IP + ":" + natPort + " на " + localIP);
    }

    /**
     * Извлекает порт NAT из данных пакета.
     *
     * @param data Данные пакета
     * @return Порт NAT или -1, если не удалось извлечь
     */
    private static int extractNatPortFromData(String data) {
        try {
            if (data.startsWith("NAT_PORT=")) {
                int endIndex = data.indexOf(';');
                if (endIndex > 0) {
                    String portStr = data.substring(9, endIndex);
                    return Integer.parseInt(portStr);
                }
            }
        } catch (Exception e) {
            System.out.println("Ошибка при извлечении порта NAT: " + e.getMessage());
        }
        return -1;
    }

    /**
     * Удаляет информацию о порте NAT из данных пакета.
     *
     * @param data Данные пакета
     * @return Данные без информации о порте NAT
     */
    private static String removeNatInfoFromData(String data) {
        int index = data.indexOf(';');
        if (index > 0 && data.startsWith("NAT_PORT=")) {
            return data.substring(index + 1);
        }
        return data;
    }

    /**
     * Перенаправляет пакет конкретному получателю по его MAC-адресу.
     *
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param senderSocket   Сокет отправителя
     */
    private static void forwardPacket(
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data,
            Socket senderSocket
    ) {
        // Проверяем, является ли получатель самим маршрутизатором
        if (ROUTER_MAC.equalsIgnoreCase(destinationMAC)) {
            // Пакет предназначен маршрутизатору, обрабатываем его
            handleRouterPacket(requestType, sourceMAC, sourceIP, data, senderSocket);
            return;
        }

        // Ищем получателя по MAC-адресу в CAM-таблице
        Socket recipientSocket;
        synchronized (tableCAM) {
            recipientSocket = tableCAM.get(destinationMAC);
        }

        // Если получатель найден и его сокет активен
        if (recipientSocket != null && !recipientSocket.isClosed()) {
            // Перенаправляем пакет получателю
            sendPacket(recipientSocket, destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);
            System.out.println("Пакет перенаправлен получателю " + destinationMAC);
        } else {
            // Получатель не найден, отправляем сообщение об ошибке отправителю
            System.out.println("MAC " + destinationMAC + " не найден в сети.");
            sendPacket(senderSocket, sourceMAC, ROUTER_MAC, ERROR,
                    sourceIP, ROUTER_IP, "Устройство с MAC " + destinationMAC + " не найдено");
        }
    }

    /**
     * Отправляет широковещательный пакет всем подключенным клиентам, кроме отправителя.
     *
     * @param destinationMAC MAC-адрес получателя (FF:FF:FF:FF:FF:FF)
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param senderSocket   Сокет отправителя
     */
    private static void broadcastPacket(
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data,
            Socket senderSocket
    ) {
        // Преобразуем тип запроса в строку для логирования
        String requestTypeStr = getRequestTypeName(requestType);

        System.out.println("Широковещательная отправка от " + sourceMAC + " типа " + requestTypeStr);

        // Определяем, является ли отправитель узлом из локальной сети
        boolean sourceIsLocal = isLocalIp(sourceIP);

        // Перебираем все записи в таблице
        synchronized (tableCAM) {
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                String recipientMAC = entry.getKey();
                Socket sock = entry.getValue();

                // Пропускаем временные записи и отправителя
                if (recipientMAC.startsWith("temp_") || sock == senderSocket || sock.isClosed()) {
                    continue;
                }

                // Если отправитель из локальной сети, то широковещательные пакеты
                // отправляем только узлам в локальной сети (не пересылаем во внешнюю)
                String recipientIP = getIpByMac(recipientMAC);
                boolean recipientIsLocal = recipientIP != null && isLocalIp(recipientIP);

                if ((sourceIsLocal && !recipientIsLocal) || (!sourceIsLocal && !recipientIsLocal && !recipientMAC.equals(ROUTER_MAC))) {
                    // Не пересылаем широковещательные пакеты между локальной и внешней сетями
                    continue;
                }

                // Отправляем пакет
                sendPacket(sock, destinationMAC, sourceMAC, requestType,
                        destinationIP, sourceIP, data);
            }
        }
    }

    /**
     * Получает IP-адрес по MAC-адресу из ARP-таблицы.
     *
     * @param mac MAC-адрес
     * @return IP-адрес или null, если MAC не найден
     */
    private static String getIpByMac(String mac) {
        synchronized (tableARP) {
            for (Map.Entry<String, String> entry : tableARP.entrySet()) {
                if (entry.getValue().equals(mac)) {
                    return entry.getKey();
                }
            }
        }
        return null;
    }

    /**
     * Преобразует массив байтов в целое число.
     */
    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    /**
     * Преобразует целое число в массив из 4 байтов.
     */
    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    /**
     * Формирует и отправляет пакет по сокету.
     *
     * @param socket         Сокет для отправки
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     */
    private static void sendPacket(
            Socket socket,
            String destinationMAC,
            String sourceMAC,
            byte requestType,
            String destinationIP,
            String sourceIP,
            String data
    ) {
        // Проверяем, что сокет существует и открыт
        if (socket == null || socket.isClosed()) return;

        try {
            // Получаем выходной поток для сокета
            OutputStream outputStream = socket.getOutputStream();

            // Форматируем каждое поле до нужного размера
            byte[] destMACBytes = padRight(destinationMAC, MAC_SIZE).getBytes();
            byte[] srcMACBytes = padRight(sourceMAC, MAC_SIZE).getBytes();
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = requestType; // Устанавливаем байт кода
            byte[] destIPBytes = padRight(destinationIP, IP_SIZE).getBytes();
            byte[] srcIPBytes = padRight(sourceIP, IP_SIZE).getBytes();
            byte[] dataBytes = data.getBytes();

            // Ограничиваем размер данных, если он превышает максимальный
            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);
                dataBytes = truncatedData;
            }

            // Записываем длину данных
            byte[] dataLengthBytes = intToByteArray(dataBytes.length);

            // Записываем все поля последовательно в выходной поток
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush();

            // Преобразуем тип запроса в строку
            String requestTypeStr = getRequestTypeName(requestType);

            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destinationMAC +
                    " (IP: " + destinationIP + "), данные: " +
                    (data.length() > 50 ? data.substring(0, 50) + "..." : data));

        } catch (IOException e) {
            System.out.println("Ошибка отправки пакета: " + e.getMessage());
        }
    }

    /**
     * Получает строковое представление типа сообщения по его коду.
     */
    private static String getRequestTypeName(byte requestType) {
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

    /**
     * Дополняет строку пробелами справа до указанной длины.
     * Если строка длиннее указанной длины, обрезает её.
     */
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }
}