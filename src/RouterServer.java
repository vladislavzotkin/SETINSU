import java.io.*;      
import java.net.*;    
import java.util.Collections;  
import java.util.HashMap;      
import java.util.Map;         
import java.util.Scanner;     


public class RouterServer {

    private static String ROUTER_MAC = "AA:BB:CC:DD:EE:FF";
    private static String ROUTER_IP = "192.168.1.1";

    private static final Map<String, Socket> tableCAM = Collections.synchronizedMap(new HashMap<>());


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

    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;

    /** IP-адрес DHCP-сервера */
    private static String dhcpServerAddress;
    /** Порт DHCP-сервера */
    private static int dhcpServerPort;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Введите IP маршрутизатора (или нажмите Enter для 192.168.1.1):");
        String input = scanner.nextLine();
        if (!input.isEmpty()) {
            ROUTER_IP = input; // Устанавливаем введенный IP-адрес
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

        // Запрашиваем адрес DHCP-сервера или используем значение по умолчанию
        System.out.println("Введите адрес DHCP-сервера (или нажмите Enter для 127.0.0.1):");
        dhcpServerAddress = "127.0.0.1"; // Адрес по умолчанию - локальный хост
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            dhcpServerAddress = input; // Устанавливаем введенный адрес DHCP-сервера
        }

        // Запрашиваем порт DHCP-сервера или используем значение по умолчанию
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

        // Выводим информацию о конфигурации маршрутизатора
        System.out.println("Запуск маршрутизатора на порту " + port);
        System.out.println("DHCP-сервер: " + dhcpServerAddress + ":" + dhcpServerPort);

        // Создаем сокет и начинаем прослушивать порт
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Маршрутизатор запущен и слушает порт " + port);

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
     * Класс для обработки подключения отдельного клиента в отдельном потоке.
     * Обрабатывает входящие пакеты и перенаправляет их соответствующим получателям.
     */
    static class ClientHandler implements Runnable {
        private final Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                // Получаем информацию о подключении клиента
                String remotePort = String.valueOf(clientSocket.getPort());
                System.out.println("Подключение клиента с порта " + remotePort);

                // Сохраняем соединение по порту до получения MAC-адреса
                // Это временная привязка, пока не получен MAC-адрес устройства
                synchronized (tableCAM) {
                    tableCAM.put(remotePort, clientSocket);
                }

                // Получаем поток ввода для чтения данных от клиента
                InputStream inputStream = clientSocket.getInputStream();
                int bytesRead;

                // Цикл чтения пакетов от клиента
                while (true) {
                    byte[] destMacBuffer = new byte[MAC_SIZE];
                    bytesRead = inputStream.read(destMacBuffer);
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
                    byte requestType = reqTypeBuffer[0]; // Используем байт как код типа запроса
                    String destinationIP = new String(destIpBuffer).trim();
                    String sourceIP = new String(srcIpBuffer).trim();
                    String data = new String(dataBuffer).trim();

                    // Получаем строковое представление типа сообщения для логирования
                    String requestTypeStr = getRequestTypeName(requestType);

                    // Выводим информацию о полученном пакете
                    System.out.println("Получен пакет: MAC получателя=" + destinationMAC +
                            ", MAC отправителя=" + sourceMAC +
                            ", Тип запроса=" + requestTypeStr +
                            ", IP получателя=" + destinationIP +
                            ", IP отправителя=" + sourceIP +
                            ", Данные=" + data);

                    // Обновляем таблицу - связываем MAC-адрес с сокетом
                    synchronized (tableCAM) {
                        // Если этого MAC-адреса еще нет в таблице, запоминаем его
                        if (!tableCAM.containsKey(sourceMAC)) {
                            tableCAM.put(sourceMAC, clientSocket);
                        }
                    }

                    // Обрабатываем пакет в зависимости от его типа
                    processPacket(requestType, destinationMAC, sourceMAC,
                            destinationIP, sourceIP, data, clientSocket);
                }

            } catch (IOException e) {
                // Обрабатываем ошибки ввода/вывода, обычно возникают при отключении клиента
                System.out.println("Клиент отключился: " + e.getMessage());
            } finally {
                // Выполняется всегда при выходе из метода
                removeFromCam(clientSocket); // Удаляем клиента из CAM-таблицы
            }
        }
    }

    /**
     * Обрабатывает пакет в зависимости от его типа.
     * Перенаправляет DHCP-запросы на DHCP-сервер, остальные пакеты - соответствующим получателям.
     *
     * @param requestType    Тип запроса
     * @param destinationMAC MAC-адрес получателя
     * @param sourceMAC      MAC-адрес отправителя
     * @param destinationIP  IP-адрес получателя
     * @param sourceIP       IP-адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента-отправителя
     */
    private static void processPacket(
            byte requestType,
            String destinationMAC,
            String sourceMAC,
            String destinationIP,
            String sourceIP,
            String data,
            Socket clientSocket
    ) {
        switch(requestType) {
            case DHCP_DISCOVER:
            case DHCP_REQUEST:
                // DHCP-запросы перенаправляем на DHCP-сервер
                forwardToDHCP(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
                break;
            default:
                // Остальные пакеты перенаправляем получателю по MAC-адресу
                forwardPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
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


            // Читаем заголовок и данные ответа
            byte[] destMacBuffer = new byte[MAC_SIZE];
            inputStream.read(destMacBuffer);

            byte[] srcMacBuffer = new byte[MAC_SIZE];
            inputStream.read(srcMacBuffer);

            byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
            inputStream.read(reqTypeBuffer);

            byte[] destIpBuffer = new byte[IP_SIZE];
            inputStream.read(destIpBuffer);

            byte[] srcIpBuffer = new byte[IP_SIZE];
            inputStream.read(srcIpBuffer);

            byte[] dataLengthBuffer = new byte[4];
            inputStream.read(dataLengthBuffer);

            int responseDataLength = byteArrayToInt(dataLengthBuffer);
            byte[] responseDataBuffer = new byte[responseDataLength];
            inputStream.read(responseDataBuffer);

            String responseDstMAC = new String(destMacBuffer).trim();
            String responseSrcMAC = new String(srcMacBuffer).trim();
            byte responseType = reqTypeBuffer[0];
            String responseDstIP = new String(destIpBuffer).trim();
            String responseSrcIP = new String(srcIpBuffer).trim();
            String responseData = new String(responseDataBuffer).trim();

            String responseTypeStr = getRequestTypeName(responseType);

            System.out.println("Получен ответ от DHCP: " + responseTypeStr + ", пересылаем клиенту " + responseDstMAC);

            sendPacket(clientSocket, responseDstMAC, responseSrcMAC, responseType,
                    responseDstIP, responseSrcIP, responseData);

        } catch (IOException e) {
            System.out.println("Ошибка подключения к DHCP-серверу: " + e.getMessage());
        }
    }

    /**
     * Перенаправляет пакет конкретному получателю по его MAC-адресу.
     * Если MAC-адрес широковещательный, отправляет пакет всем клиентам.
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
        // Проверяем, является ли пакет широковещательным
        if ("FF:FF:FF:FF:FF:FF".equalsIgnoreCase(destinationMAC)) {
            // Если да, отправляем его всем подключенным клиентам
            broadcastPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, senderSocket);
            return;
        }

        // Проверяем, является ли получатель самим маршрутизатором
        if (ROUTER_MAC.equalsIgnoreCase(destinationMAC)) {
            // Преобразуем тип запроса в строку для логирования
            String requestTypeStr = getRequestTypeName(requestType);

            System.out.println("Получен пакет для маршрутизатора типа " + requestTypeStr);
            return; // Пакет предназначен маршрутизатору, обработка завершена
        }

        // Ищем получателя по MAC-адресу в таблице
        Socket recipientSocket;
        synchronized (tableCAM) {
            recipientSocket = tableCAM.get(destinationMAC);
        }

        // Если получатель найден и его сокет активен
        if (recipientSocket != null && !recipientSocket.isClosed()) {
            // Перенаправляем пакет получателю
            sendPacket(recipientSocket, destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);
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
     * @param destinationMAC MAC-адрес получателя
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
        // Преобразуем тип запроса в строку
        String requestTypeStr = getRequestTypeName(requestType);

        System.out.println("Широковещательная отправка от " + sourceMAC + " типа " + requestTypeStr);

        // Перебираем все записи в таблице
        synchronized (tableCAM) {
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                Socket sock = entry.getValue();
                // Отправляем пакет всем клиентам, кроме отправителя
                if (sock != senderSocket && !sock.isClosed()) {
                    sendPacket(sock, destinationMAC, sourceMAC, requestType,
                            destinationIP, sourceIP, data);
                }
            }
        }
    }

    /**
     * Преобразует массив байтов в целое число .
     *
     * @param bytes Массив из 4 байтов
     * @return Целое число
     */
    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |   // Сдвигаем первый байт на 24 бита и маскируем
                ((bytes[1] & 0xFF) << 16) |  // Сдвигаем второй байт на 16 бит и маскируем
                ((bytes[2] & 0xFF) << 8) |   // Сдвигаем третий байт на 8 бит и маскируем
                (bytes[3] & 0xFF);           // Маскируем четвертый байт
    }

    /**
     * Преобразует целое число в массив из 4 байтов.
     *
     * @param value Целое число
     * @return Массив из 4 байтов
     */
    private static byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),  // Старший байт (сдвиг на 24 бита)
                (byte)(value >>> 16),  // Второй байт (сдвиг на 16 бит)
                (byte)(value >>> 8),   // Третий байт (сдвиг на 8 бит)
                (byte)value            // Младший байт
        };
    }

    /**
     * Формирует и отправляет сетевой пакет по сокету.
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

            // Записываем длину данных (4 байта)
            byte[] dataLengthBytes = intToByteArray(dataBytes.length);

            // Записываем в выходной поток
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush(); // Сбрасываем буфер

            // Преобразуем тип запроса в строку для логирования
            String requestTypeStr = getRequestTypeName(requestType);

            // Выводим информацию об отправленном пакете
            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destinationMAC +
                    " (IP: " + destinationIP + "), данные: " + data);

        } catch (IOException e) {
            // Обрабатываем ошибки отправки пакета
            System.out.println("Ошибка отправки пакета: " + e.getMessage());
        }
    }


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
            default: return "UNKNOWN(" + requestType + ")";
        }
    }

    /**
     * Дополняет строку пробелами справа до указанной длины.
     * Если строка длиннее указанной длины, обрезает её.
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

    /**
     * Удаляет сокет клиента из таблицы при отключении.
     *
     * @param clientSocket Сокет отключившегося клиента
     */
    private static void removeFromCam(Socket clientSocket) {
        synchronized (tableCAM) {
            String removedKey = null;
            // Находим ключ (MAC-адрес) по значению (сокету)
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                if (entry.getValue() == clientSocket) {
                    removedKey = entry.getKey();
                    break;
                }
            }
            // Если ключ найден, удаляем запись из таблицы
            if (removedKey != null) {
                tableCAM.remove(removedKey);
                System.out.println("Клиент " + removedKey + " отключен.");
            }
        }
    }
}