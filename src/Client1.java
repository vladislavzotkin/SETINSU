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

    private static String CLIENT_MAC;              // MAC адрес клиента, задается при запуске
    private static String CLIENT_IP = "0.0.0.0";   // IP адрес клиента, изначально не назначен
    private static boolean ipAssigned = false;     // Флаг, указывающий, назначен ли IP-адрес

    private static String ROUTER_ADDRESS;
    private static int ROUTER_PORT;
    private static final String ROUTER_MAC = "AA:BB:CC:DD:EE:FF";

    private Socket socket;
    private OutputStream outputStream;  // Поток для отправки данных
    private InputStream inputStream;    // Поток для получения данных

    // Переменные для хранения состояния DHCP процесса
    private volatile String dhcpOfferedIP = null;  // IP адрес, предложенный DHCP сервером
    private volatile List<String> availableIPs = new ArrayList<>();  // Список доступных IP адресов
    private volatile boolean dhcpAckReceived = false;  // Флаг получения подтверждения DHCP
    private volatile CountDownLatch dhcpLatch = new CountDownLatch(1);  // Механизм синхронизации потоков для DHCP

    /**
     * Таблица ARP  для хранения IP и MAC.
     */
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());

    private volatile String arpResponseMAC = null;  // MAC адрес, полученный в ответ на ARP запрос

    private int clientNumber;            // Номер клиента
    private boolean manualIPSelection;   // Флаг для определения способа выбора IP (ручной/автоматический)


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        int clientNumber = 1;  // Номер клиента по умолчанию

        // Запрашиваем MAC адрес клиента
        System.out.println("Введите MAC адрес клиента (или нажмите Enter для AA:BB:CC:DD:EE:0" + clientNumber + "):");
        CLIENT_MAC = scanner.nextLine();
        if (CLIENT_MAC.isEmpty()) {
            CLIENT_MAC = "AA:BB:CC:DD:EE:0" + clientNumber;
        }

        // Запрашиваем адрес коммутатора
        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для 192.168.1.1):");
        ROUTER_ADDRESS = scanner.nextLine();
        if (ROUTER_ADDRESS.isEmpty()) {
            ROUTER_ADDRESS = "127.0.0.1";
        }

        // Запрашиваем порт
        System.out.println("Введите порт маршрутизатора (или нажмите Enter для 8081):");
        String portInput = scanner.nextLine();
        ROUTER_PORT = portInput.isEmpty() ? 8081 : Integer.parseInt(portInput);

        // Запрашиваем выбор IP (ручной или автоматический)
        System.out.println("Хотите вручную выбрать IP-адрес? (true/false):");
        boolean manualIPSelection = Boolean.parseBoolean(scanner.nextLine());  // Парсим строку в boolean

        Client1 client = new Client1();
        client.clientNumber = clientNumber;  // Устанавливаем номер клиента
        client.manualIPSelection = manualIPSelection;  // Устанавливаем флаг ручного выбора IP
        client.start(scanner);  // Запускаем клиента, передавая ему сканнер для чтения ввода
    }


    public void start(Scanner scanner) {
        try {
            // Подключаемся к маршрутизатору
            socket = new Socket(ROUTER_ADDRESS, ROUTER_PORT);  // Создаем сокет для подключения к маршрутизатору
            outputStream = socket.getOutputStream();  // Получаем выходной поток для отправки данных
            inputStream = socket.getInputStream();  // для получения данных
            System.out.println("Клиент " + clientNumber + " подключился к " + ROUTER_ADDRESS + ":" + ROUTER_PORT);

            // Запускаем поток для прослушивания входящих сообщений
            Thread listenThread = new Thread(this::listenForMessages);
            listenThread.setDaemon(true);  // Устанавливаем поток как демон (завершится при завершении основного потока)
            listenThread.start();

            Thread.sleep(1000);
            performDhcpProcess(scanner);  // Запускаем процесс получения IP адреса через DHCP

            // Проверяем, удалось ли получить IP адрес
            if (!ipAssigned) {
                System.out.println("Не удалось получить IP-адрес через DHCP");
                socket.close();
                return;
            }

            System.out.println("IP-адрес " + CLIENT_IP + " успешно получен через DHCP");

            while (true) {
                System.out.println("\nМеню клиента " + clientNumber + ":");
                System.out.println("1. Показать информацию о клиенте");
                System.out.println("2. Обновить IP-адрес (новый DHCP запрос)");
                System.out.println("3. Отправить сообщение другому клиенту");
                System.out.println("4. Показать ARP таблицу");
                System.out.println("5. Выход");
                System.out.print("Выберите действие: ");

                String choice = scanner.nextLine();

                if (choice.equals("1")) {
                    // Показываем информацию о клиенте
                    System.out.println("Информация о клиенте:");
                    System.out.println("Номер клиента: " + clientNumber);
                    System.out.println("MAC-адрес: " + CLIENT_MAC);
                    System.out.println("IP-адрес: " + CLIENT_IP);
                    System.out.println("Статус: " + (ipAssigned ? "IP назначен" : "IP не назначен"));
                }
                else if (choice.equals("2")) {
                    // Обновляем IP адрес через новый DHCP запрос
                    System.out.println("Запуск нового DHCP запроса...");
                    // Сбрасываем все переменные, связанные с DHCP
                    dhcpOfferedIP = null;
                    availableIPs.clear();
                    dhcpAckReceived = false;
                    ipAssigned = false;
                    CLIENT_IP = "0.0.0.0";
                    dhcpLatch = new CountDownLatch(1);  // Создаем новый объект для синхронизации

                    // Запускаем процесс получения IP
                    performDhcpProcess(scanner);
                }
                else if (choice.equals("3")) {
                    if (!ipAssigned) {  // Проверяем, есть ли у нас IP адрес
                        System.out.println("Сначала необходимо получить IP-адрес");
                        continue;
                    }

                    // Запрашиваем IP адрес получателя
                    System.out.print("Введите IP адрес назначения: ");
                    String destinationIP = scanner.nextLine();

                    // Запрашиваем текст сообщения
                    System.out.print("Введите сообщение: ");
                    String data = scanner.nextLine();

                    // Получаем MAC адрес через ARP запрос, если он неизвестен
                    String destinationMAC = getMacAddress(destinationIP);
                    if (destinationMAC == null) {  // Если MAC адрес не удалось получить
                        System.out.println("ARP не удался. Не получилось узнать MAC для IP: " + destinationIP);
                        continue;
                    }

                    // Отправляем с типом PING
                    sendMessage(destinationMAC, CLIENT_MAC, PING, destinationIP, CLIENT_IP, data);
                    System.out.println("Сообщение отправлено");
                }
                else if (choice.equals("4")) {
                    // Показываем содержимое ARP таблицы
                    System.out.println("ARP таблица:");
                    if (tableARP.isEmpty()) {  // Проверяем, пуста ли таблица
                        System.out.println("Таблица пуста");
                    } else {
                        // Выводим все записи из таблицы
                        for (Map.Entry<String, String> entry : tableARP.entrySet()) {
                            System.out.println("IP: " + entry.getKey() + " -> MAC: " + entry.getValue());
                        }
                    }
                }
                else if (choice.equals("5")) {
                    // Выход из программы
                    System.out.println("Завершение работы клиента " + clientNumber);
                    socket.close();  // Закрываем сокет
                    break;  // Выходим из цикла
                }
                else {
                    // Неверный ввод
                    System.out.println("Неверный выбор, попробуйте снова");
                }
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Выполняет процесс получения IP адреса через DHCP.
     * Включает отправку DHCP DISCOVER, получение DHCP OFFER,
     * выбор IPадреса (автоматически или вручную) и отправку DHCP REQUEST.
     */
    private void performDhcpProcess(Scanner scanner) {
        try {
            // Отправляем DHCP Discover для поиска DHCP сервера
            System.out.println("Отправка DHCP Discover...");
            // Используем широковещательный MAC и IP адрес
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_DISCOVER, "255.255.255.255", "0.0.0.0", "");

            Thread.sleep(3000);

            //  Выбираем IP адрес для запроса
            String requestedIP = null;  // Переменная для хранения выбранного IP

            if (dhcpOfferedIP != null) {
                // Если получили предложение IP через DHCP Offer, используем его
                requestedIP = dhcpOfferedIP;
                System.out.println("Используем предложенный IP: " + requestedIP);
            } else if (!availableIPs.isEmpty()) {
                // Если получили список доступных IP, но не получили DHCP Offer
                if (manualIPSelection) {
                    // Режим ручного выбора IP
                    // Показываем доступные IP-адреса и запрашиваем выбор пользователя
                    System.out.println("\nДоступные IP-адреса:");
                    for (int i = 0; i < availableIPs.size(); i++) {
                        System.out.println((i + 1) + ". " + availableIPs.get(i));
                    }

                    // Запрашиваем выбор пользователя, проверяя корректность ввода
                    int choice = -1;
                    while (choice < 1 || choice > availableIPs.size()) {
                        System.out.print("Выберите IP (1-" + availableIPs.size() + "): ");
                        try {
                            choice = Integer.parseInt(scanner.nextLine());  // Пытаемся преобразовать ввод в число
                        } catch (NumberFormatException e) {
                            System.out.println("Пожалуйста, введите число");  // Сообщение об ошибке при неверном формате
                        }
                    }

                    // Используем выбранный IP из списка (индексация в списке начинается с 0, поэтому choice - 1)
                    requestedIP = availableIPs.get(choice - 1);
                    System.out.println("Выбран IP: " + requestedIP);
                } else {
                    // Режим автоматического выбора IP (берем первый доступный)
                    requestedIP = availableIPs.get(0);
                    System.out.println("Автоматически выбран первый доступный IP: " + requestedIP);
                }
            } else {
                // Если не получили ни DHCP Offer, ни список доступных IP
                System.out.println("Не получен ни DHCP Offer, ни список доступных IP, процесс не завершен");
                return;  // Прерываем процесс
            }

            // Отправляем DHCP Request для запроса выбранного IP
            System.out.println("Отправка DHCP Request для IP: " + requestedIP);
            // Используем широковещательный MAC и IP адрес
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_REQUEST, "255.255.255.255", "0.0.0.0", requestedIP);

            Thread.sleep(3000);

            // Проверяем результат процесса
            if (dhcpAckReceived) {
                // Если получили подтверждение, сохраняем IP и устанавливаем флаг
                CLIENT_IP = requestedIP;
                ipAssigned = true;
                System.out.println("DHCP процесс завершен успешно, получен IP: " + CLIENT_IP);
            } else {
                // Если не получили подтверждение
                System.out.println("Не получен DHCP ACK, процесс не завершен");
            }

        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Получает MAC адрес для указанного IP адреса.
     * Если MAC адрес есть в ARP таблице, возвращает его напрямую.
     * Если нет, отправляет ARP запрос и ждет ответа.
     *
     */
    private String getMacAddress(String ip) {
        if (tableARP.containsKey(ip)) {
            // Если MAC адрес уже есть в таблице, просто возвращаем его
            return tableARP.get(ip);
        } else {
            // Если MAC адреса нет в таблице, отправляем ARP-запрос
            // Используем широковещательный MAC
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, ARP_REQUEST, ip, CLIENT_IP, "");

            // Ждем ответа на ARP запрос
            try {
                int tries = 0;  // Счетчик попыток
                // Ждем до 10 попыток с интервалом
                while (arpResponseMAC == null && tries < 10) {
                    Thread.sleep(200);  // Пауза между попытками
                    tries++;
                }
                if (arpResponseMAC != null) {
                    // Если получили ответ, сохраняем MAC в таблицу и возвращаем его
                    String mac = arpResponseMAC;
                    arpResponseMAC = null;  // Сбрасываем переменную для следующего запроса
                    tableARP.put(ip, mac);  // Обновляем ARP таблицу
                    return mac;
                }
            } catch (InterruptedException e) {
                // Обрабатываем исключение при прерывании потока
                e.printStackTrace();  // Выводим стек вызовов для отладки
            }
        }
        return null;
    }

    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    /**
     * Прослушивает входящие сообщения от маршрутизатора.
     * Этот метод запускается в отдельном потоке и работает непрерывно,
     * считывая пакеты из входного потока и передавая их на обработку.
     */
    private void listenForMessages() {
        try {
            while (true) {
                // Читаем MAC адрес назначения (первое поле пакета)
                byte[] destMacBuffer = new byte[MAC_SIZE];  // Создаем буфер для MAC адреса назначения
                int bytesRead = inputStream.read(destMacBuffer);  // Читаем байты в буфер
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
     * Выполняет различные действия для разных типов пакетов: DHCP, PING/PONG, ARP.
     *
     * @param destinationMAC MAC адрес получателя
     * @param sourceMAC      MAC адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP адрес отправителя
     * @param data           Данные пакета
     */
    private void handleIncomingMessage(String destinationMAC, String sourceMAC, byte requestType,
                                       String destinationIP, String sourceIP, String data) {
        String requestTypeStr;
        switch (requestType) {
            case DHCP_DISCOVER: requestTypeStr = "DHCP_DISCOVER"; break;
            case DHCP_OFFER: requestTypeStr = "DHCP_OFFER"; break;
            case DHCP_REQUEST: requestTypeStr = "DHCP_REQUEST"; break;
            case DHCP_ACK: requestTypeStr = "DHCP_ACK"; break;
            case ERROR: requestTypeStr = "ERROR"; break;
            case DHCP_AVAILABLE_IPS: requestTypeStr = "DHCP_AVAILABLE_IPS"; break;
            case PING: requestTypeStr = "PING"; break;
            case PONG: requestTypeStr = "PONG"; break;
            case ARP_REQUEST: requestTypeStr = "ARP_REQUEST"; break;
            case ARP_RESPONSE: requestTypeStr = "ARP_RESPONSE"; break;
            default: requestTypeStr = "UNKNOWN(" + requestType + ")";
        }

        String msg = String.format(
                "Клиент%d получил пакет -> DestMAC:%s, SrcMAC:%s, Type:%s, DestIP:%s, SrcIP:%s, Data:%s",
                clientNumber, destinationMAC, sourceMAC, requestTypeStr, destinationIP, sourceIP, data
        );
        System.out.println(msg);

        // Обновляем ARP таблицу, сохраняя MAC адрес отправителя (если это не широковещательный адрес)
        if (!sourceMAC.equals("FF:FF:FF:FF:FF:FF") && !sourceIP.equals("0.0.0.0")) {
            tableARP.put(sourceIP, sourceMAC);  // Добавляем запись в ARP таблицу
        }

        // Проверяем, что пакет предназначен для нас (по MAC или широковещательный)
        if (destinationMAC.equals("FF:FF:FF:FF:FF:FF")) {
            // Для широковещательных пакетов проверяем тип
            // Принимаем только DHCP и ARP запросы, остальные только если они адресованы нам по IP
            if (requestType != DHCP_OFFER && requestType != DHCP_ACK &&
                    requestType != DHCP_AVAILABLE_IPS && requestType != ARP_REQUEST) {
                if (!destinationIP.equals("255.255.255.255") && !destinationIP.equals(CLIENT_IP) &&
                        !destinationIP.equals("0.0.0.0")) {
                    return;
                }
            }
        } else if (!destinationMAC.equals(CLIENT_MAC)) {
            // Если MAC не широковещательный и не наш, игнорируем пакет
            return;
        }

        // Обрабатываем пакет в зависимости от его типа
        switch (requestType) {
            case DHCP_AVAILABLE_IPS: {
                // Обработка списка доступных IP адресов
                if (!data.isEmpty()) {
                    // Разбиваем строку на отдельные IP адреса по запятым
                    String[] ips = data.split(",");
                    availableIPs = new ArrayList<>(Arrays.asList(ips));  // Сохраняем список IP
                    System.out.println("Получен список доступных IP-адресов: " + String.join(", ", ips));
                }
                break;
            }
            case DHCP_OFFER: {
                // Обработка предложения IP адреса от DHCP-сервера
                if (dhcpOfferedIP == null) {  // Проверяем, не получали ли мы уже предложение
                    dhcpOfferedIP = data;  // Сохраняем предложенный IP
                    System.out.println("Получен DHCP Offer с IP: " + dhcpOfferedIP);
                }
                break;
            }
            case DHCP_ACK: {
                // Обработка подтверждения выделения IP-адреса
                dhcpAckReceived = true;  // Устанавливаем флаг получения подтверждения
                System.out.println("Получен DHCP ACK для IP: " + data);
                break;
            }
            case ERROR: {
                // Обработка сообщения об ошибке
                System.out.println("Получена ошибка: " + data);
                break;
            }
            case PING: {
                // Обработка запроса PING
                // Автоматически отвечаем PONG на входящий PING
                System.out.println("Получен PING от " + sourceIP + ", отправляем PONG...");
                sendMessage(sourceMAC, CLIENT_MAC, PONG, sourceIP, CLIENT_IP, data);
                break;
            }
            case PONG: {
                // Обработка ответа PONG
                System.out.println("Получен PONG от " + sourceIP + " с сообщением: " + data);
                break;
            }
            case ARP_REQUEST: {
                // Обработка запроса ARP (запрос MAC адреса)
                // Отвечаем только если запрос для нашего IP
                if (destinationIP.equals(CLIENT_IP)) {
                    System.out.println("Получен ARP запрос от " + sourceIP + ", отправляем ответ...");
                    sendMessage(sourceMAC, CLIENT_MAC, ARP_RESPONSE, sourceIP, CLIENT_IP, CLIENT_MAC);
                }
                break;
            }
            case ARP_RESPONSE: {
                // Обработка ответа ARP
                if (destinationMAC.equals(CLIENT_MAC)) {  // Проверяем, что ответ направлен нам
                    // Извлекаем MAC из данных или используем MAC отправителя, если данные пустые
                    arpResponseMAC = data.isEmpty() ? sourceMAC : data;
                    System.out.println("Получен ARP ответ от " + sourceIP + " с MAC: " + arpResponseMAC);
                }
                break;
            }
        }
    }

    /**
     * Формирует и отправляет пакет через сокет.
     *
     * @param destMAC  MAC-адрес получателя
     * @param srcMAC   MAC-адрес отправителя
     * @param reqType  Тип запроса
     * @param destIP   IP-адрес получателя
     * @param srcIP    IP-адрес отправителя
     * @param data     Данные пакета
     */
    private void sendMessage(String destMAC, String srcMAC, byte reqType,
                             String destIP, String srcIP, String data) {
        try {

            byte[] destMACBytes = padRight(destMAC, MAC_SIZE).getBytes();
            byte[] srcMACBytes = padRight(srcMAC, MAC_SIZE).getBytes();
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = reqType;
            byte[] destIPBytes = padRight(destIP, IP_SIZE).getBytes();
            byte[] srcIPBytes = padRight(srcIP, IP_SIZE).getBytes();
            byte[] dataBytes = data.getBytes();


            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];            // Создаем буфер максимального размера
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);  // Копируем только часть данных
                dataBytes = truncatedData;                                 // Используем усеченные данные
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

            String requestTypeStr;
            switch (reqType) {
                case DHCP_DISCOVER: requestTypeStr = "DHCP_DISCOVER"; break;
                case DHCP_OFFER: requestTypeStr = "DHCP_OFFER"; break;
                case DHCP_REQUEST: requestTypeStr = "DHCP_REQUEST"; break;
                case DHCP_ACK: requestTypeStr = "DHCP_ACK"; break;
                case ERROR: requestTypeStr = "ERROR"; break;
                case DHCP_AVAILABLE_IPS: requestTypeStr = "DHCP_AVAILABLE_IPS"; break;
                case PING: requestTypeStr = "PING"; break;
                case PONG: requestTypeStr = "PONG"; break;
                case ARP_REQUEST: requestTypeStr = "ARP_REQUEST"; break;
                case ARP_RESPONSE: requestTypeStr = "ARP_RESPONSE"; break;
                default: requestTypeStr = "UNKNOWN(" + reqType + ")";
            }

            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destMAC +
                    " (IP: " + destIP + "), данные: " + data);

        } catch (IOException e) {
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());  // Выводим сообщение об ошибке
        }
    }

    /**
     * Дополняет строку пробелами справа до указанной длины.
     * Если строка длиннее указанной длины, обрезает ее.
     *
     * @param s Исходная строка
     * @param n Требуемая длина
     * @return Строка нужной длины, дополненная пробелами справа
     */
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }
}