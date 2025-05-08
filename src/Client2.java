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

    private static String CLIENT_MAC;
    private static String CLIENT_IP = "0.0.0.0";
    private static boolean ipAssigned = false;

    private static String ROUTER_ADDRESS;
    private static int ROUTER_PORT;
    private static final String ROUTER_MAC = "AA:BB:CC:DD:EE:FF";

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

    private int clientNumber;
    private boolean manualIPSelection; // Флаг для ручного выбора IP

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        int clientNumber = 2;

        System.out.println("Введите MAC адрес клиента (или нажмите Enter для AA:BB:CC:DD:EE:0" + clientNumber + "):");
        CLIENT_MAC = scanner.nextLine();
        if (CLIENT_MAC.isEmpty()) {
            CLIENT_MAC = "AA:BB:CC:DD:EE:0" + clientNumber;
        }

        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для 192.168.1.1):");
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

            // Расширенное меню для пользователя с добавленным функционалом
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
                    if (!ipAssigned) {
                        System.out.println("Сначала необходимо получить IP-адрес");
                        continue;
                    }

                    System.out.print("Введите IP адрес назначения: ");
                    String destinationIP = scanner.nextLine();

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

    private void performDhcpProcess(Scanner scanner) {
        try {
            // Отправляем DHCP Discover
            System.out.println("Отправка DHCP Discover...");
            sendMessage("FF:FF:FF:FF:FF:FF", CLIENT_MAC, DHCP_DISCOVER, "255.255.255.255", "0.0.0.0", "");

            // Ждем получения информации от сервера
            Thread.sleep(3000); // Ждем 3 секунды

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
            Thread.sleep(3000);

            if (dhcpAckReceived) {
                CLIENT_IP = requestedIP;
                ipAssigned = true;
                System.out.println("DHCP процесс завершен успешно, получен IP: " + CLIENT_IP);
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

    // Прослушивание входящих сообщений от маршрутизатора
    private void listenForMessages() {
        try {
            while (true) {
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

                // Читаем длину данных
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

        if (!sourceMAC.equals("FF:FF:FF:FF:FF:FF") && !sourceIP.equals("0.0.0.0")) {
            tableARP.put(sourceIP, sourceMAC);
        }

        if (destinationMAC.equals("FF:FF:FF:FF:FF:FF")) {
            // Для DHCP и ARP принимаем широковещательные сообщения
            if (requestType != DHCP_OFFER && requestType != DHCP_ACK &&
                    requestType != DHCP_AVAILABLE_IPS && requestType != ARP_REQUEST) {
                if (!destinationIP.equals("255.255.255.255") && !destinationIP.equals(CLIENT_IP) &&
                        !destinationIP.equals("0.0.0.0")) {
                    return;
                }
            }
        } else if (!destinationMAC.equals(CLIENT_MAC)) {

            return;
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
        }
    }

    private void sendMessage(String destMAC, String srcMAC, byte reqType,
                             String destIP, String srcIP, String data) {
        try {
            // Форматируем каждое поле до нужного размера
            byte[] destMACBytes = padRight(destMAC, MAC_SIZE).getBytes();
            byte[] srcMACBytes = padRight(srcMAC, MAC_SIZE).getBytes();
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = reqType;
            byte[] destIPBytes = padRight(destIP, IP_SIZE).getBytes();
            byte[] srcIPBytes = padRight(srcIP, IP_SIZE).getBytes();
            byte[] dataBytes = data.getBytes();

            // Ограничиваем размер данных
            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);
                dataBytes = truncatedData;
            }

            // Записываем длину данных
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
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());
        }
    }

    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }
}