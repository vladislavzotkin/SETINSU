/**
 * Класс ExternalClient1 представляет внешний сетевой узел, находящийся за пределами локальной сети.
 * Взаимодействует с маршрутизатором и клиентами внутренней сети через NAT.
 *
 * Имеет статический IP-адрес из внешней сети
 * Может принимать и отправлять пакеты узлам внутренней сети
 * Поддерживает взаимодействие через NAT
 * Поддерживает HTTP для обмена HTML-страницами
 */
import java.io.*;          
import java.net.*;          
import java.util.Scanner;   
import java.util.Map;     
import java.util.HashMap;  
import java.util.Collections; 

public class ExternalClient1 {

    // Размеры полей в байтах
    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;


    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;
    private static final byte ARP_RESPONSE = 23;


    private static final byte HTTP_GET = 40;         // Код для запроса HTML-страницы
    private static final byte HTTP_RESPONSE = 41;    // Код для ответа с HTML-страницей

    private static String CLIENT_MAC = "BB:AA:CC:DD:EE:01";  // MAC-адрес внешнего клиента
    private static String CLIENT_IP = "203.0.113.10";       // Статический IP-адрес из внешней сети
    private static boolean ipAssigned = true;               // Флаг наличия IP-адреса

    private static String ROUTER_ADDRESS;            // IP-адрес маршрутизатора
    private static int ROUTER_PORT;                  // Порт маршрутизатора
    private static final String ROUTER_MAC = "AA:BB:CC:DD:EE:FF"; // MAC-адрес маршрутизатора
    private static String ROUTER_PUBLIC_IP = "203.0.113.1";  // Публичный IP-адрес маршрутизатора

    private Socket socket;                           // Сокет для соединения с маршрутизатором
    private OutputStream outputStream;               // Поток для отправки данных
    private InputStream inputStream;                 // Поток для получения данных

    // IP-MAC
    private static final Map<String, String> tableARP = Collections.synchronizedMap(new HashMap<>());

    private String htmlPage;                         // Содержимое HTML-страницы


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Введите MAC адрес внешнего клиента (или нажмите Enter для " + CLIENT_MAC + "):");
        String mac = scanner.nextLine();
        if (!mac.isEmpty()) {
            CLIENT_MAC = mac;
        }

        // Запрашиваем IP-адрес внешнего клиента
        System.out.println("Введите IP адрес внешнего клиента (или нажмите Enter для " + CLIENT_IP + "):");
        String ip = scanner.nextLine();
        if (!ip.isEmpty()) {
            CLIENT_IP = ip;
        }

        // Запрашиваем адрес маршрутизатора
        System.out.println("Введите адрес маршрутизатора (или нажмите Enter для 127.0.0.1):");
        ROUTER_ADDRESS = scanner.nextLine();
        if (ROUTER_ADDRESS.isEmpty()) {
            ROUTER_ADDRESS = "127.0.0.1";
        }

        // Запрашиваем публичный IP маршрутизатора
        System.out.println("Введите публичный IP-адрес маршрутизатора (или нажмите Enter для " + ROUTER_PUBLIC_IP + "):");
        String publicIp = scanner.nextLine();
        if (!publicIp.isEmpty()) {
            ROUTER_PUBLIC_IP = publicIp;
        }

        // Запрашиваем порт маршрутизатора
        System.out.println("Введите порт маршрутизатора (или нажмите Enter для 8081):");
        String portInput = scanner.nextLine();
        ROUTER_PORT = portInput.isEmpty() ? 8081 : Integer.parseInt(portInput);

        // Создаем и запускаем внешний клиент
        ExternalClient1 client = new ExternalClient1();
        client.start(scanner);
    }

    public void start(Scanner scanner) {
        try {
            // Подключение к роутеру
            socket = new Socket(ROUTER_ADDRESS, ROUTER_PORT);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            System.out.println("Внешний клиент подключился к " + ROUTER_ADDRESS + ":" + ROUTER_PORT);

            // Запускаем поток для прослушивания входящих сообщений
            Thread listenThread = new Thread(this::listenForMessages);
            listenThread.setDaemon(true);
            listenThread.start();

            // Добавляем маршрутизатор в ARP-таблицу
            tableARP.put(ROUTER_PUBLIC_IP, ROUTER_MAC);

            // Инициализируем HTML-страницу
            initializeHtmlPage();
            System.out.println("HTML-страница инициализирована");

            // Меню
            while (true) {
                System.out.println("\nМеню внешнего клиента:");
                System.out.println("1. Показать информацию о клиенте");
                System.out.println("2. Отправить сообщение в локальную сеть");
                System.out.println("3. Показать ARP таблицу");
                System.out.println("4. Получить HTML-страницу внутреннего клиента");
                System.out.println("5. Выход");
                System.out.print("Выберите действие: ");

                String choice = scanner.nextLine();

                if (choice.equals("1")) {
                    // Показываем информацию о клиенте
                    System.out.println("Информация о внешнем клиенте:");
                    System.out.println("MAC-адрес: " + CLIENT_MAC);
                    System.out.println("IP-адрес: " + CLIENT_IP);
                    System.out.println("Статус: Подключен (внешняя сеть)");
                }
                else if (choice.equals("2")) {
                    // Отправляем сообщение в локальную сеть через NAT
                    System.out.println("Введите IP адрес назначения в локальной сети:");
                    String destination = scanner.nextLine();

                    System.out.print("Введите сообщение: ");
                    String data = scanner.nextLine();

                    // Получаем MAC адрес маршрутизатора для отправки
                    String destinationMAC = ROUTER_MAC;

                    // Отправляем сообщение на маршрутизатор (он выполнит трансляцию через NAT)
                    sendMessage(destinationMAC, CLIENT_MAC, PING, destination, CLIENT_IP, data);
                    System.out.println("Сообщение отправлено через NAT");
                }
                else if (choice.equals("3")) {
                    // Показываем ARP таблицу
                    System.out.println("ARP таблица внешнего клиента:");
                    if (tableARP.isEmpty()) {
                        System.out.println("Таблица пуста");
                    } else {
                        for (Map.Entry<String, String> entry : tableARP.entrySet()) {
                            System.out.println("IP: " + entry.getKey() + " -> MAC: " + entry.getValue());
                        }
                    }
                }
                else if (choice.equals("4")) {
                    // Запрашиваем HTML-страницу внутреннего клиента
                    System.out.print("Введите IP-адрес внутреннего клиента: ");
                    String internalIP = scanner.nextLine();
                    getHtmlPage(internalIP);
                }
                else if (choice.equals("5")) {
                    // Выход из программы
                    System.out.println("Завершение работы внешнего клиента");
                    socket.close();
                    break;
                }
                else {
                    System.out.println("Неверный выбор, попробуйте снова");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Инициализирует HTML-страницу внешнего клиента с информацией о нем.
     */
    private void initializeHtmlPage() {
        htmlPage = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>Внешний клиент</title>\n" +
                "    <style>\n" +
                "        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }\n" +
                "        h1 { color: #e74c3c; }\n" +
                "        .info { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }\n" +
                "        .subtitle { color: #666; }\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <h1>Внешний сервер</h1>\n" +
                "    <div class=\"info\">\n" +
                "        <h2>Сетевая информация:</h2>\n" +
                "        <p><strong>MAC-адрес:</strong> " + CLIENT_MAC + "</p>\n" +
                "        <p><strong>IP-адрес:</strong> " + CLIENT_IP + "</p>\n" +
                "        <p><strong>Расположение:</strong> Внешняя сеть (за NAT)</p>\n" +
                "        <p class=\"subtitle\">Страница сгенерирована: " + new java.util.Date() + "</p>\n" +
                "    </div>\n" +
                "</body>\n" +
                "</html>";
    }

    /**
     * Отправляет HTTP-запрос для получения HTML-страницы внутреннего клиента через NAT.
     */
    private void getHtmlPage(String internalIP) {
        System.out.println("Отправка HTTP GET запроса клиенту " + internalIP + " через NAT");

        // Отправляем HTTP GET запрос маршрутизатору, который выполнит NAT-трансляцию
        sendMessage(ROUTER_MAC, CLIENT_MAC, HTTP_GET, internalIP, CLIENT_IP, "");
    }

    /**
     * Прослушивает входящие сообщения от маршрутизатора.
     */
    private void listenForMessages() {
        try {
            while (true) {
                // Читаем MAC-адрес назначения
                byte[] destMacBuffer = new byte[MAC_SIZE];
                int bytesRead = inputStream.read(destMacBuffer);
                if (bytesRead != MAC_SIZE) {
                    if (bytesRead == -1) break;
                    continue;
                }

                // Читаем MAC-адрес отправителя
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

                // Читаем IP-адрес отправителя
                byte[] srcIpBuffer = new byte[IP_SIZE];
                bytesRead = inputStream.read(srcIpBuffer);
                if (bytesRead != IP_SIZE) continue;

                // Читаем длину данных
                byte[] dataLengthBuffer = new byte[4];
                bytesRead = inputStream.read(dataLengthBuffer);
                if (bytesRead != 4) continue;

                // Преобразуем длину данных в число
                int dataLength = byteArrayToInt(dataLengthBuffer);
                if (dataLength > MAX_DATA_SIZE || dataLength < 0) {
                    dataLength = MAX_DATA_SIZE;
                }

                // Читаем данные
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

                // Проверяем, предназначен ли пакет для нас
                if (destinationMAC.equals(CLIENT_MAC) || destinationMAC.equals("FF:FF:FF:FF:FF:FF")) {
                    // Обрабатываем пакет
                    handleIncomingMessage(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);
                }
            }
        } catch (IOException e) {
            if (!socket.isClosed()) {
                System.out.println("Соединение с маршрутизатором прервано: " + e.getMessage());
            }
        }
    }

    /**
     * Обрабатывает входящие пакеты в зависимости от их типа.
     * Особая обработка для пакетов, прошедших через NAT.
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
                "Внешний клиент получил пакет -> DestMAC:%s, SrcMAC:%s, Type:%s, DestIP:%s, SrcIP:%s, Data:%s",
                destinationMAC, sourceMAC, requestTypeStr, destinationIP, sourceIP,
                (data.length() > 50 ? data.substring(0, 50) + "..." : data)
        );
        System.out.println(msg);

        // Сохраняем MAC адрес источника в ARP таблицу
        if (!sourceMAC.equals("FF:FF:FF:FF:FF:FF") && !sourceIP.equals("0.0.0.0")) {
            tableARP.put(sourceIP, sourceMAC);
        }

        // Проверяем, содержит ли пакет информацию о порте NAT
        String cleanData = data;
        if (data.startsWith("NAT_PORT=")) {
            int endIndex = data.indexOf(';');
            if (endIndex > 0) {
                cleanData = data.substring(endIndex + 1);
            }
        }

        // Обрабатываем пакет в зависимости от типа
        switch (requestType) {
            case PING: {
                // Получен ping-запрос, отвечаем pong
                System.out.println("Получен PING от " + sourceIP + ", отправляем PONG...");
                sendMessage(sourceMAC, CLIENT_MAC, PONG, sourceIP, CLIENT_IP, cleanData);
                break;
            }
            case PONG: {
                // Получен pong-ответ на наш ping
                System.out.println("Получен PONG от " + sourceIP + " с сообщением: " + cleanData);
                break;
            }
            case ARP_REQUEST: {
                // Получен ARP-запрос
                if (destinationIP.equals(CLIENT_IP)) {
                    System.out.println("Получен ARP запрос от " + sourceIP + ", отправляем ответ...");
                    sendMessage(sourceMAC, CLIENT_MAC, ARP_RESPONSE, sourceIP, CLIENT_IP, CLIENT_MAC);
                }
                break;
            }
            case HTTP_GET: {
                // Получен запрос на HTML-страницу
                System.out.println("Получен HTTP GET от клиента " + sourceIP);
                sendMessage(sourceMAC, CLIENT_MAC, HTTP_RESPONSE, sourceIP, CLIENT_IP, htmlPage);
                break;
            }
            case HTTP_RESPONSE: {
                // Получен ответ с HTML-страницей
                System.out.println("Получен HTTP ответ от " + sourceIP);
                System.out.println("Получена HTML-страница:");
                System.out.println("------- HTML НАЧАЛО -------");
                System.out.println(cleanData);
                System.out.println("-------- HTML КОНЕЦ --------");
                break;
            }
        }
    }

    /**
     * Отправляет сетевое сообщение через маршрутизатор.
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

            // Записываем все поля последовательно в поток
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush();

            String requestTypeStr = getRequestTypeName(reqType);
            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destMAC +
                    " (IP: " + destIP + "), данные: " +
                    (data.length() > 50 ? data.substring(0, 50) + "..." : data));

        } catch (IOException e) {
            System.out.println("Ошибка отправки сообщения: " + e.getMessage());
        }
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
     * Возвращает строковое представление типа сообщения по его коду.
     */
    private String getRequestTypeName(byte requestType) {
        switch (requestType) {
            case PING: return "PING";
            case PONG: return "PONG";
            case ARP_REQUEST: return "ARP_REQUEST";
            case ARP_RESPONSE: return "ARP_RESPONSE";
            case HTTP_GET: return "HTTP_GET";
            case HTTP_RESPONSE: return "HTTP_RESPONSE";
            default: return "UNKNOWN(" + requestType + ")";
        }
    }


    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }
}