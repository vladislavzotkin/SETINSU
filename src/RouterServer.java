import java.io.*;              
import java.net.*;             
import java.util.Collections;  
import java.util.HashMap;      
import java.util.Map;           
import java.util.Scanner;     

public class RouterServer {

    private static String ROUTER_MAC = "AA:BB:CC:DD:EE:FF";
    private static String ROUTER_IP = "192.168.1.1";

    /**
     * Мак и сокет таблица
     */
    private static final Map<String, Socket> tableCAM = Collections.synchronizedMap(new HashMap<>());

    private static final byte DHCP_DISCOVER = 5;   // Запрос клиента на поиск сервера
    private static final byte DHCP_OFFER = 6;      // Ответ сервера с предложением ip
    private static final byte DHCP_REQUEST = 7;    // Запрос на конкретный ip
    private static final byte DHCP_ACK = 8;        // Подтверждение выдачи
    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10; // Список доступных адресов


    private static final byte PING = 20;
    private static final byte PONG = 21;
    private static final byte ARP_REQUEST = 22;    // Запрос на определение MAC по IP
    private static final byte ARP_RESPONSE = 23;   // Ответ

    // Размеры
    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1; // тип запроса
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;  // размер данных

    private static String dhcpServerAddress;        // Адрес DHCP сервера
    private static int dhcpServerPort;              // Порт сервера


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Запрашиваем IP адрес
        System.out.println("Введите IP маршрутизатора (или нажмите Enter для 192.168.1.1):");
        String input = scanner.nextLine();
        if (!input.isEmpty()) {
            ROUTER_IP = input;
        }

        // Запрашиваем MAC адрес
        System.out.println("Введите MAC маршрутизатора (или нажмите Enter для AA:BB:CC:DD:EE:FF):");
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            ROUTER_MAC = input;
        }

        // Запрашиваем порт для
        System.out.println("Введите порт для маршрутизатора (или нажмите Enter для 8081):");
        int port = 8081;
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            try {
                port = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Неверный формат порта, используется порт 8081");
            }
        }

        // Запрашиваем адрес DHCP сервера, при пустом вводе используем умолчанию 127.0.0.1
        System.out.println("Введите адрес DHCP-сервера (или нажмите Enter для 127.0.0.1):");
        dhcpServerAddress = "127.0.0.1";
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            dhcpServerAddress = input;
        }

        // Запрашиваем порт DHCP сервера
        System.out.println("Введите порт DHCP-сервера (или нажмите Enter для 8080):");
        dhcpServerPort = 8080;
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            try {
                dhcpServerPort = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Неверный формат порта DHCP, используется порт 8080");
            }
        }

        // информация о запуске
        System.out.println("Запуск маршрутизатора на порту " + port);
        System.out.println("DHCP-сервер: " + dhcpServerAddress + ":" + dhcpServerPort);

        // Создаем сокет, используя try with resources для автоматического закрытия ресурсов
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Маршрутизатор запущен и слушает порт " + port);  // Выводим сообщение об успешном запуске

            // Бесконечный цикл для приема новых подключений
            while (true) {
                Socket clientSocket = serverSocket.accept();  // Блокирующий вызов, ожидаем подключения клиента
                new Thread(new ClientHandler(clientSocket)).start();  // Создаем и запускаем новый поток для обработки клиента
            }
        } catch (IOException e) {
            System.err.println("Ошибка запуска: " + e.getMessage());
        }
    }

    /**
     * Класс для обработки подключений клиентов.
     * Каждое подключение обрабатывается в отдельном потоке.
     */
    static class ClientHandler implements Runnable {
        private final Socket clientSocket;  // Сокет для связи с клиентом


        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;  // Сохраняем сокет клиента
        }

        @Override
        public void run() {
            try {
                // Получаем порт до получения MAC адреса
                String remotePort = String.valueOf(clientSocket.getPort());  // Преобразуем номер порта в строку
                System.out.println("Подключение клиента с порта " + remotePort);

                // сохраняем соединение по порту до получения адреса
                synchronized (tableCAM) {
                    tableCAM.put(remotePort, clientSocket);  // Добавляем клиента по номеру
                }

                InputStream inputStream = clientSocket.getInputStream();  // Получаем входной поток от клиента
                int bytesRead;  // Переменная для хранения количества прочитанных байт

                // Бесконечный цикл чтения пакетов от клиента
                while (true) {
                    // Читаем MAC адрес назначения
                    byte[] destMacBuffer = new byte[MAC_SIZE];  // Создаем буфер
                    bytesRead = inputStream.read(destMacBuffer);  // Читаем байты
                    if (bytesRead != MAC_SIZE) {  // Проверяем размер
                        if (bytesRead == -1) break;
                        continue;
                    }

                    // MAC адрес отправителя
                    byte[] srcMacBuffer = new byte[MAC_SIZE];
                    bytesRead = inputStream.read(srcMacBuffer);
                    if (bytesRead != MAC_SIZE) continue;

                    // тип запроса
                    byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
                    bytesRead = inputStream.read(reqTypeBuffer);
                    if (bytesRead != REQUEST_TYPE_SIZE) continue;

                    // Читаем IP адрес назначения
                    byte[] destIpBuffer = new byte[IP_SIZE];
                    bytesRead = inputStream.read(destIpBuffer);
                    if (bytesRead != IP_SIZE) continue;

                    // IP адрес отправителя
                    byte[] srcIpBuffer = new byte[IP_SIZE];
                    bytesRead = inputStream.read(srcIpBuffer);
                    if (bytesRead != IP_SIZE) continue;

                    // Читаем длину данных
                    byte[] dataLengthBuffer = new byte[4];
                    bytesRead = inputStream.read(dataLengthBuffer);  // Читаем байты в буфер
                    if (bytesRead != 4) continue;

                    // Преобразуем байты длины данных в целое число
                    int dataLength = byteArrayToInt(dataLengthBuffer);  // Преобразуем массив байт в int
                    if (dataLength > MAX_DATA_SIZE || dataLength < 0) {  // Проверяем, что длина данных в допустимых пределах
                        dataLength = MAX_DATA_SIZE;  // Если длина превышает максимум, ограничиваем ее
                    }

                    // Читаем сами данные
                    byte[] dataBuffer = new byte[dataLength];  // Создаем буфер для данных нужной длины
                    bytesRead = inputStream.read(dataBuffer);
                    if (bytesRead != dataLength) continue;

                    // Преобразуем в строки
                    String destinationMAC = new String(destMacBuffer).trim();
                    String sourceMAC = new String(srcMacBuffer).trim();
                    byte requestType = reqTypeBuffer[0];  // Извлекаем байт типа запроса
                    String destinationIP = new String(destIpBuffer).trim();
                    String sourceIP = new String(srcIpBuffer).trim();
                    String data = new String(dataBuffer).trim();

                    String requestTypeStr;
                    switch (requestType) {
                        case DHCP_DISCOVER: requestTypeStr = "DHCP_DISCOVER"; break;  // Запрос на поиск DHCP сервера
                        case DHCP_OFFER: requestTypeStr = "DHCP_OFFER"; break;        // Предложение IP адреса
                        case DHCP_REQUEST: requestTypeStr = "DHCP_REQUEST"; break;     // Запрос на конкретный IP
                        case DHCP_ACK: requestTypeStr = "DHCP_ACK"; break;            // Подтверждение IP
                        case ERROR: requestTypeStr = "ERROR"; break;
                        case DHCP_AVAILABLE_IPS: requestTypeStr = "DHCP_AVAILABLE_IPS"; break;  // Список доступных
                        case PING: requestTypeStr = "PING"; break;
                        case PONG: requestTypeStr = "PONG"; break;
                        case ARP_REQUEST: requestTypeStr = "ARP_REQUEST"; break;
                        case ARP_RESPONSE: requestTypeStr = "ARP_RESPONSE"; break;
                        default: requestTypeStr = "UNKNOWN(" + requestType + ")";
                    }

                    System.out.println("Получен пакет: MAC получателя=" + destinationMAC +
                            ", MAC отправителя=" + sourceMAC +
                            ", Тип запроса=" + requestTypeStr +
                            ", IP получателя=" + destinationIP +
                            ", IP отправителя=" + sourceIP +
                            ", Данные=" + data);

                    // Обновляем, если MAC адрес отправителя еще не зарегистрирован
                    synchronized (tableCAM) {
                        // Если еще нет, добавляем его
                        if (!tableCAM.containsKey(sourceMAC)) {
                            tableCAM.put(sourceMAC, clientSocket);  // Сохраняем сокет по адресу
                        }
                    }

                    // Обрабатываем в зависимости от  типа
                    processPacket(requestType, destinationMAC, sourceMAC,
                            destinationIP, sourceIP, data, clientSocket);
                }

            } catch (IOException e) {
                System.out.println("Клиент отключился: " + e.getMessage());
            } finally {
                removeFromCam(clientSocket);
            }
        }
    }

    /**
     * Обрабатывает в зависимости от его типа.
     * @param requestType    Тип запроса
     * @param destinationMAC MAC адрес получателя
     * @param sourceMAC      MAC адрес отправителя
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента отправителя
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
            case DHCP_DISCOVER:         // Если это запрос на поиск DHCP сервера
            case DHCP_REQUEST:          // Или запрос на получение конкретного IP адреса
                // Перенаправляем запрос на DHCP сервер
                forwardToDHCP(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
                break;
            default:                    // Для всех остальных типов
                // Остальные пакеты перенаправляем получателю по MAC адресу
                forwardPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, clientSocket);
                break;
        }
    }

    /**
     * Перенаправляет на DHCP сервер и возвращает ответ клиенту.
     *
     * @param destinationMAC MAC адрес получателя
     * @param sourceMAC      MAC адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP адрес отправителя
     * @param data           Данные пакета
     * @param clientSocket   Сокет клиента отправителя
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
        try (Socket dhcpSocket = new Socket(dhcpServerAddress, dhcpServerPort)) {  // Создаем сокет для подключения к DHCP серверу

            String requestTypeStr;
            switch (requestType) {
                case DHCP_DISCOVER: requestTypeStr = "DHCP_DISCOVER"; break;
                case DHCP_OFFER: requestTypeStr = "DHCP_OFFER"; break;
                case DHCP_REQUEST: requestTypeStr = "DHCP_REQUEST"; break;
                case DHCP_ACK: requestTypeStr = "DHCP_ACK"; break;
                case ERROR: requestTypeStr = "ERROR"; break;
                case DHCP_AVAILABLE_IPS: requestTypeStr = "DHCP_AVAILABLE_IPS"; break;
                default: requestTypeStr = "UNKNOWN(" + requestType + ")";
            }

            System.out.println("Перенаправление DHCP пакета на сервер " + dhcpServerAddress + ":" + dhcpServerPort);

            // Отправляем пакет DHCP серверу
            sendPacket(dhcpSocket, destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);

            // Ожидаем ответа от DHCP сервера и перенаправляем клиенту
            InputStream inputStream = dhcpSocket.getInputStream();  // Получаем входной поток от DHCP сервера

            // Читаем MAC адрес назначения из ответа DHCP сервера
            byte[] destMacBuffer = new byte[MAC_SIZE];  // Создаем буфер для MAC адреса назначения
            inputStream.read(destMacBuffer);

            // Читаем MAC адрес отправителя
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

            // Преобразуем байты длины данных в целое число
            int responseDataLength = byteArrayToInt(dataLengthBuffer);

            // Читаем данные из ответа DHCP сервера
            byte[] responseDataBuffer = new byte[responseDataLength];  // Создаем буфер для данных нужной длины
            inputStream.read(responseDataBuffer);

            // Преобразуем в строки
            String responseDstMAC = new String(destMacBuffer).trim();
            String responseSrcMAC = new String(srcMacBuffer).trim();
            byte responseType = reqTypeBuffer[0];
            String responseDstIP = new String(destIpBuffer).trim();
            String responseSrcIP = new String(srcIpBuffer).trim();
            String responseData = new String(responseDataBuffer).trim();

            String responseTypeStr;
            switch (responseType) {
                case DHCP_DISCOVER: responseTypeStr = "DHCP_DISCOVER"; break;
                case DHCP_OFFER: responseTypeStr = "DHCP_OFFER"; break;
                case DHCP_REQUEST: responseTypeStr = "DHCP_REQUEST"; break;
                case DHCP_ACK: responseTypeStr = "DHCP_ACK"; break;
                case ERROR: responseTypeStr = "ERROR"; break;
                case DHCP_AVAILABLE_IPS: responseTypeStr = "DHCP_AVAILABLE_IPS"; break;
                default: responseTypeStr = "UNKNOWN(" + responseType + ")";
            }

            System.out.println("Получен ответ от DHCP: " + responseTypeStr + ", пересылаем клиенту " + responseDstMAC);

            // Перенаправляем ответ от DHCP сервера клиенту
            sendPacket(clientSocket, responseDstMAC, responseSrcMAC, responseType,
                    responseDstIP, responseSrcIP, responseData);

        } catch (IOException e) {
            System.out.println("Ошибка подключения к DHCP-серверу: " + e.getMessage());
        }
    }

    /**
     * Перенаправляет пакет получателю по MAC-адресу.
     * Если MAC адрес получателя широковещательный (FF:FF:FF:FF:FF:FF),
     * то пакет отправляется всем клиентам.
     *
     * @param destinationMAC MAC адрес получателя
     * @param sourceMAC      MAC адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP бадрес отправителя
     * @param data           Данные пакета
     * @param senderSocket   Сокет клиента отправителя
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
        // Если это широковещательный
        if ("FF:FF:FF:FF:FF:FF".equalsIgnoreCase(destinationMAC)) {
            // Отправляем пакет всем клиентам
            broadcastPacket(destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data, senderSocket);
            return;
        }

        // Если получатель - маршрутизатор
        if (ROUTER_MAC.equalsIgnoreCase(destinationMAC)) {
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

            System.out.println("Получен пакет для маршрутизатора типа " + requestTypeStr);
            return;  // Завершаем, т.к. пакет адресован самому маршрутизатору
        }

        // Ищем получателя по MAC в таблице
        Socket recipientSocket;
        synchronized (tableCAM) {
            recipientSocket = tableCAM.get(destinationMAC);  // Получаем сокет получателя по MAC адресу
        }

        // Если получатель найден и его сокет активен
        if (recipientSocket != null && !recipientSocket.isClosed()) {
            // Отправляем
            sendPacket(recipientSocket, destinationMAC, sourceMAC, requestType, destinationIP, sourceIP, data);
        } else {
            // Если получатель не найден
            System.out.println("MAC " + destinationMAC + " не найден в сети.");
            sendPacket(senderSocket, sourceMAC, ROUTER_MAC, ERROR,
                    sourceIP, ROUTER_IP, "Устройство с MAC " + destinationMAC + " не найдено");
        }
    }

    /**
     * Отправляет пакет всем клиентам, кроме отправителя (широковещательная рассылка).
     *
     * @param destinationMAC MAC адрес получателя (должен быть FF:FF:FF:FF:FF:FF)
     * @param sourceMAC      MAC адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP адрес отправителя
     * @param data           Данные пакета
     * @param senderSocket   Сокет клиента отправителя
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

        System.out.println("Широковещательная отправка от " + sourceMAC + " типа " + requestTypeStr);

        // Проходим по всем клиентам
        synchronized (tableCAM) {
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                Socket sock = entry.getValue();  // Получаем сокет клиента
                // Отправляем пакет всем клиентам, кроме отправителя
                if (sock != senderSocket && !sock.isClosed()) {
                    sendPacket(sock, destinationMAC, sourceMAC, requestType,
                            destinationIP, sourceIP, data);
                }
            }
        }
    }

    /**
     * Преобразует массив из 4 байт в целое число
     */
    private static int byteArrayToInt(byte[] bytes) {
        // Преобразуем 4 байта в int, учитывая порядок байт
        return ((bytes[0] & 0xFF) << 24) |  // Первый байт сдвигаем на 24 бита
                ((bytes[1] & 0xFF) << 16) |  // Второй байт сдвигаем на 16 бит
                ((bytes[2] & 0xFF) << 8) |   // Третий байт сдвигаем на 8 бит
                (bytes[3] & 0xFF);           // Четвертый байт (младший байт)
    }

    /**
     * Преобразует целое число в массив из 4 байт.
     */
    private static byte[] intToByteArray(int value) {
        // Преобразуем int в массив из 4 байт, учитывая порядок байт
        return new byte[] {
                (byte)(value >>> 24),        // Извлекаем старший байт (сдвиг на 24 бита вправо)
                (byte)(value >>> 16),        // Извлекаем второй байт (сдвиг на 16 бит вправо)
                (byte)(value >>> 8),         // Извлекаем третий байт (сдвиг на 8 бит вправо)
                (byte)value                  // Извлекаем младший байт
        };
    }

    /**
     * Формирует и отправляет пакет через указанный сокет.
     *
     * @param socket         Сокет, через который отправляется пакет
     * @param destinationMAC MAC адрес получателя
     * @param sourceMAC      MAC адрес отправителя
     * @param requestType    Тип запроса
     * @param destinationIP  IP адрес получателя
     * @param sourceIP       IP адрес отправителя
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
        // Проверяем, что сокет существует и не закрыт
        if (socket == null || socket.isClosed()) return;

        try {
            // Получаем выходной поток сокета
            OutputStream outputStream = socket.getOutputStream();

            // Форматируем каждое поле до нужного размера
            byte[] destMACBytes = padRight(destinationMAC, MAC_SIZE).getBytes();
            byte[] srcMACBytes = padRight(sourceMAC, MAC_SIZE).getBytes();
            byte[] reqTypeBytes = new byte[REQUEST_TYPE_SIZE];
            reqTypeBytes[0] = requestType;
            byte[] destIPBytes = padRight(destinationIP, IP_SIZE).getBytes();
            byte[] srcIPBytes = padRight(sourceIP, IP_SIZE).getBytes();
            byte[] dataBytes = data.getBytes();

            // Ограничиваем размер данных, если он превышает максимально допустимый
            if (dataBytes.length > MAX_DATA_SIZE) {
                byte[] truncatedData = new byte[MAX_DATA_SIZE];
                System.arraycopy(dataBytes, 0, truncatedData, 0, MAX_DATA_SIZE);
                dataBytes = truncatedData;
            }

            // Записываем длину данных (4 байта)
            byte[] dataLengthBytes = intToByteArray(dataBytes.length);

            // Записываем все поля в выходной поток
            outputStream.write(destMACBytes);
            outputStream.write(srcMACBytes);
            outputStream.write(reqTypeBytes);
            outputStream.write(destIPBytes);
            outputStream.write(srcIPBytes);
            outputStream.write(dataLengthBytes);
            outputStream.write(dataBytes);
            outputStream.flush();

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

            System.out.println("Отправлен пакет: " + requestTypeStr + " -> " + destinationMAC +
                    " (IP: " + destinationIP + "), данные: " + data);

        } catch (IOException e) {
            System.out.println("Ошибка отправки пакета: " + e.getMessage());
        }
    }

    /**
     * Дополняет строку пробелами справа до указанной длины.
     * Если строка длиннее указанной длины, обрезает ее.
     */
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);  // Используем для выравнивания по левому краю
    }

    /**
     * Удаляет сокет из таблицы при отключении клиента.
     */
    private static void removeFromCam(Socket clientSocket) {
        synchronized (tableCAM) {
            String removedKey = null;
            // Ищем ключ  по значению (сокету)
            for (Map.Entry<String, Socket> entry : tableCAM.entrySet()) {
                if (entry.getValue() == clientSocket) {
                    removedKey = entry.getKey();  // Запоминаем ключ для удаления
                    break;
                }
            }
            // Если ключ найден, удаляем его из таблицы
            if (removedKey != null) {
                tableCAM.remove(removedKey);
                System.out.println("Клиент " + removedKey + " отключен.");
            }
        }
    }
}