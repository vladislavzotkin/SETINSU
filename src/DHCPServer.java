import java.io.*;               // Импорт классов ввода-вывода для работы с потоками данных
import java.net.*;              // Импорт сетевых классов для работы с сокетами и сетевыми соединениями
import java.util.Collections;   // Импорт утилитарного класса для создания безопасных коллекций
import java.util.HashMap;       // Импорт класса для хранения пар ключ-значение
import java.util.Map;           // Импорт интерфейса для работы с отображениями
import java.util.Scanner;       // Импорт класса для чтения пользовательского ввода
import java.util.ArrayList;     // Импорт класса для работы с динамическими массивами
import java.util.List;          // Импорт интерфейса для работы со списками


public class DHCPServer {


    private static String SERVER_MAC = "AA:BB:22:DD:EE:FF";
    private static String SERVER_IP = "127.0.0.1";

    private static final int IP_POOL_START = 10;   // Начало диапазона
    private static final int IP_POOL_END = 100;    // Конец диапазона

    /**
     * Массив для хранения состояния IP-адресов в пуле.
     * true = IP адрес занят (арендован клиентом)
     * false = IP адрес свободен (доступен для выдачи)
     *
     * Индекс массива соответствует последнему октету IP адреса.
     * Например, ipPool[15] соответствует адресу 192.168.1.15
     */
    private static final boolean[] ipPool = new boolean[IP_POOL_END + 1];

    /**
     * Таблица аренд IP адресов.
     * Ключ - MAC адрес клиента, значение - выделенный ему IP адрес.
     */
    private static final Map<String, String> dhcpLeases = Collections.synchronizedMap(new HashMap<>());

    private static final byte DHCP_DISCOVER = 5;   // Запрос клиента на поиск DHCP сервера
    private static final byte DHCP_OFFER = 6;      // Ответ сервера с предложением IP адреса
    private static final byte DHCP_REQUEST = 7;    // Запрос на конкретный
    private static final byte DHCP_ACK = 8;        // Подтверждение выдачи
    private static final byte ERROR = 9;
    private static final byte DHCP_AVAILABLE_IPS = 10; // Код для отправки списка доступных

    private static final int MAC_SIZE = 17;
    private static final int REQUEST_TYPE_SIZE = 1;
    private static final int IP_SIZE = 15;
    private static final int MAX_DATA_SIZE = 1024;


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Запрашиваем IP адрес DHCP сервера
        System.out.println("Введите IP DHCP-сервера (или нажмите Enter для 127.0.0.1):");
        String input = scanner.nextLine();
        if (!input.isEmpty()) {
            SERVER_IP = input;
        }

        // Запрашиваем MAC адрес
        System.out.println("Введите MAC DHCP-сервера (или нажмите Enter для AA:BB:22:DD:EE:FF):");
        input = scanner.nextLine();
        if (!input.isEmpty()) {  // Если строка не пустая, используем введенное значение
            SERVER_MAC = input;
        }

        // Запрашиваем порт
        System.out.println("Введите порт для DHCP-сервера (или нажмите Enter для 8080):");
        int port = 8080;
        input = scanner.nextLine();
        if (!input.isEmpty()) {
            try {
                port = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Неверный формат порта, используется порт 8080");
            }
        }

        System.out.println("Запуск DHCP-сервера на порту " + port);

        // Создаем сокет
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("DHCP-сервер запущен и слушает порт " + port);

            // для приема новых подключений
            while (true) {
                Socket clientSocket = serverSocket.accept();  // Блокирующий вызов, ожидаем подключения клиента
                new Thread(new ClientHandler(clientSocket)).start();  // Создаем и запускаем новый поток для обработки клиента
            }
        } catch (IOException e) {
            System.err.println("Ошибка запуска: " + e.getMessage());
        }
    }

    /**
     * Внутренний класс для обработки подключений клиентов.
     * Каждое подключение обрабатывается в отдельном потоке.
     * Отвечает за чтение пакетов от клиента и их обработку.
     */
    static class ClientHandler implements Runnable {
        private final Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;  // Сохраняем сокет клиента
        }

        @Override
        public void run() {
            try {
                System.out.println("Подключение от " + clientSocket.getInetAddress() + ":" + clientSocket.getPort());

                InputStream inputStream = clientSocket.getInputStream();  // Получаем входной поток от клиента
                int bytesRead;

                // Бесконечный цикл чтения пакетов от клиента
                while (true) {
                    // Читаем MAC адрес
                    byte[] destMacBuffer = new byte[MAC_SIZE];  // Создаем буфер для MAC адреса назначения
                    bytesRead = inputStream.read(destMacBuffer);  // Читаем байты в буфер
                    if (bytesRead != MAC_SIZE) {  // Проверяем, что прочитано нужное количество байт
                        if (bytesRead == -1) break;
                        continue;
                    }

                    // Читаем MAC адрес отправителя
                    byte[] srcMacBuffer = new byte[MAC_SIZE];
                    bytesRead = inputStream.read(srcMacBuffer);
                    if (bytesRead != MAC_SIZE) continue;

                    // тип запроса
                    byte[] reqTypeBuffer = new byte[REQUEST_TYPE_SIZE];
                    bytesRead = inputStream.read(reqTypeBuffer);
                    if (bytesRead != REQUEST_TYPE_SIZE) continue;

                    // IP адрес назначения
                    byte[] destIpBuffer = new byte[IP_SIZE];
                    bytesRead = inputStream.read(destIpBuffer);
                    if (bytesRead != IP_SIZE) continue;

                    // IP адрес отправителя
                    byte[] srcIpBuffer = new byte[IP_SIZE];
                    bytesRead = inputStream.read(srcIpBuffer);
                    if (bytesRead != IP_SIZE) continue;

                    // Читаем длину данных
                    byte[] dataLengthBuffer = new byte[4];
                    bytesRead = inputStream.read(dataLengthBuffer);
                    if (bytesRead != 4) continue;

                    // Преобразуем байты длины данных в целое число
                    int dataLength = byteArrayToInt(dataLengthBuffer);  // Преобразуем массив байт в int
                    if (dataLength > MAX_DATA_SIZE || dataLength < 0) {  // Проверяем, что длина данных в допустимых пределах
                        dataLength = MAX_DATA_SIZE;  // Если длина превышает максимум, ограничиваем ее
                    }

                    // Читаем сами данные
                    byte[] dataBuffer = new byte[dataLength];
                    bytesRead = inputStream.read(dataBuffer);  // Читаем байты в буфер
                    if (bytesRead != dataLength) continue;

                    // Преобразуем все в строки
                    String destinationMAC = new String(destMacBuffer).trim();
                    String sourceMAC = new String(srcMacBuffer).trim();
                    byte requestType = reqTypeBuffer[0];  // Извлекаем байт типа запроса
                    String destinationIP = new String(destIpBuffer).trim();
                    String sourceIP = new String(srcIpBuffer).trim();
                    String data = new String(dataBuffer).trim();

                    System.out.println("Получен пакет: MAC получателя=" + destinationMAC +
                            ", MAC отправителя=" + sourceMAC +
                            ", Тип запроса=" + requestType +
                            ", IP получателя=" + destinationIP +
                            ", IP отправителя=" + sourceIP +
                            ", Данные=" + data);

                    processPacket(requestType, sourceMAC, data, clientSocket);
                }

            } catch (IOException e) {
                System.out.println("Соединение закрыто: " + e.getMessage());  // Выводим информацию о закрытии соединения
            }
        }
    }

    /**
     * Обрабатывает пакет в зависимости от его типа.
     * DISCOVER и REQUEST.
     *
     * @param requestType  Тип запроса
     * @param sourceMAC    MAC адрес отправителя
     * @param data         Данные пакета
     * @param clientSocket Сокет клиента-отправителя
     */
    private static void processPacket(
            byte requestType,
            String sourceMAC,
            String data,
            Socket clientSocket
    ) {
        switch(requestType) {
            case DHCP_DISCOVER:    // Если это запрос на поиск DHCP сервера клиент ищет IP
                processDhcpDiscover(sourceMAC, clientSocket);
                break;
            case DHCP_REQUEST:     // Если это запрос на конкретный IP адрес
                processDhcpRequest(sourceMAC, data, clientSocket);
                break;
            default:               // Для всех остальных типов пакетов
                System.out.println("Получен неизвестный тип пакета: " + requestType);
                break;
        }
    }

    /**
     * Обрабатывает DHCP DISCOVER запрос от клиента.
     * Отправляет клиенту список доступных IP адресов и предлагает один из них.
     * Если у клиента уже есть аренда, предлагает тот же IP адрес.
     */
    private static void processDhcpDiscover(String clientMAC, Socket clientSocket) {
        System.out.println("DHCP Discover от " + clientMAC);

        // Проверяем, есть ли уже аренда IP адреса для этого MAC адреса
        String assignedIP = dhcpLeases.get(clientMAC);  // Получаем ранее выданный IP

        // Собираем список доступных IP адресов
        List<String> availableIPs = getAvailableIPs(5);

        // Проверяем, есть ли свободные IP адреса в пуле
        if (availableIPs.isEmpty()) {
            System.out.println("Нет свободных IP-адресов!");
            return;
        }

        // Формируем строку со списком доступных адресов
        StringBuilder ipListStr = new StringBuilder();
        for (String ip : availableIPs) {
            ipListStr.append(ip).append(",");
        }

        // Удаляем последнюю запятую, если список не пуст
        if (ipListStr.length() > 0) {
            ipListStr.deleteCharAt(ipListStr.length() - 1);  // Удаляем последнюю запятую
        }

        System.out.println("Отправка DHCP_AVAILABLE_IPS с доступными IP: " + ipListStr.toString());

        // Отправляем клиенту список доступных IP адресов
        sendPacket(clientSocket, clientMAC, SERVER_MAC, DHCP_AVAILABLE_IPS,
                "255.255.255.255", SERVER_IP, ipListStr.toString());

        // Проверяем, есть ли у клиента уже выданный IP адрес
        if (assignedIP != null) {  // Если у клиента уже есть аренда
            // Выводим информацию о повторном предложении
            System.out.println("Клиент " + clientMAC + " уже имеет аренду IP " + assignedIP);

            // Отправляем DHCP OFFER с ранее выданным IP адресом
            sendPacket(clientSocket, clientMAC, SERVER_MAC, DHCP_OFFER,
                    assignedIP, SERVER_IP, assignedIP);
        } else {  // Если у клиента нет аренды
            // Предлагаем первый свободный IP адрес из списка
            String firstIP = availableIPs.get(0);

            System.out.println("Отправка DHCP Offer с IP " + firstIP + " для " + clientMAC);

            // Отправляем DHCP OFFER с новым IP адресом
            sendPacket(clientSocket, clientMAC, SERVER_MAC, DHCP_OFFER,
                    firstIP, SERVER_IP, firstIP);
        }
    }

    /**
     * Получает список доступных IP адресов из пула.
     */
    private static List<String> getAvailableIPs(int limit) {
        List<String> availableIPs = new ArrayList<>();  // Создаем список для хранения доступных IP
        int count = 0;  // Счетчик найденных свободных

        synchronized (ipPool) {
            // Проходим по всему диапазону
            for (int i = IP_POOL_START; i <= IP_POOL_END && count < limit; i++) {
                if (!ipPool[i]) {  // Если адрес свободен (значение false)
                    availableIPs.add("192.168.1." + i);  // Формируем полный IP и добавляем в список
                    count++;  // Увеличиваем счетчик найденных
                }
            }
        }

        return availableIPs;
    }

    /**
     * Обрабатывает DHCP REQUEST запрос от клиента.
     * Проверяет доступность запрошенного IP адреса и выделяет его клиенту.
     *
     * @param clientMAC    MAC-адрес клиента
     * @param requestedIP  Запрошенный IP-адрес
     * @param clientSocket Сокет клиента
     */
    private static void processDhcpRequest(String clientMAC, String requestedIP, Socket clientSocket) {

        System.out.println("DHCP Request от " + clientMAC + " для IP " + requestedIP);

        // Проверяем, совпадает ли запрошенный IP с ранее выданным этому клиенту
        String assignedIP = dhcpLeases.get(clientMAC);  // Получаем ранее выданный IP

        // Если IP уже был выдан этому клиенту, просто подтверждаем
        if (assignedIP != null && assignedIP.equals(requestedIP)) {
            System.out.println("Отправка DHCP ACK для существующей аренды " + assignedIP);

            // Отправляем DHCP ACK с подтверждением аренды
            sendPacket(clientSocket, clientMAC, SERVER_MAC, DHCP_ACK,
                    assignedIP, SERVER_IP, assignedIP);
            return;
        }

        // Проверяем корректность
        String[] parts = requestedIP.split("\\.");  // Разбиваем IP на октеты
        if (parts.length != 4) {  // Должно быть 4 октета
            // Отправляем сообщение об ошибке при неверном формате IP
            sendPacket(clientSocket, clientMAC, SERVER_MAC, ERROR,
                    "0.0.0.0", SERVER_IP, "Неверный формат IP");
            return;
        }

        try {
            // Извлекаем последний октет IP адреса и проверяем, входит ли он в допустимый диапазон
            int lastOctet = Integer.parseInt(parts[3]);  // Парсим последний октет
            if (lastOctet < IP_POOL_START || lastOctet > IP_POOL_END) {  // Проверяем диапазон
                // Отправляем сообщение об ошибке при IP вне допустимого диапазона
                sendPacket(clientSocket, clientMAC, SERVER_MAC, ERROR,
                        "0.0.0.0", SERVER_IP, "IP вне допустимого диапазона");
                return;
            }

            synchronized (ipPool) {
                // Проверяем, не занят ли запрошенный IP адрес другим клиентом
                if (ipPool[lastOctet]) {  // Если IP уже занят
                    // Проверяем, не выдан ли этот IP другому клиенту
                    boolean isAssignedToOther = false;
                    // Проходим по всем активным арендам
                    for (Map.Entry<String, String> entry : dhcpLeases.entrySet()) {
                        // Если IP уже выдан и не текущему клиенту
                        if (entry.getValue().equals(requestedIP) && !entry.getKey().equals(clientMAC)) {
                            isAssignedToOther = true;  // Флаг, что IP выдан другому клиенту
                            break;
                        }
                    }

                    // Если IP выдан другому клиенту
                    if (isAssignedToOther) {
                        sendPacket(clientSocket, clientMAC, SERVER_MAC, ERROR,
                                "0.0.0.0", SERVER_IP, "IP уже выдан другому клиенту");
                        return;
                    }
                }

                // Если у клиента уже была аренда другого IP, освобождаем его
                if (assignedIP != null) {  // Если у клиента уже был IP
                    String[] oldParts = assignedIP.split("\\.");  // Разбиваем старый IP на октеты
                    if (oldParts.length == 4) {  // Проверяем корректность формата
                        try {
                            // Извлекаем последний октет старого IP
                            int oldLastOctet = Integer.parseInt(oldParts[3]);
                            // Если октет в допустимом диапазоне пула
                            if (oldLastOctet >= IP_POOL_START && oldLastOctet <= IP_POOL_END) {
                                ipPool[oldLastOctet] = false;  // Освобождаем старый IP
                            }
                        } catch (NumberFormatException e) {
                        }
                    }
                }

                // Выделяем запрошенный IP клиенту
                ipPool[lastOctet] = true;  // Помечаем IP как занятый
                dhcpLeases.put(clientMAC, requestedIP);  // Добавляем или обновляем запись в таблице аренд

                // Отправляем подтверждение выделения IP
                System.out.println("Отправка DHCP ACK для нового IP " + requestedIP);
                sendPacket(clientSocket, clientMAC, SERVER_MAC, DHCP_ACK,
                        requestedIP, SERVER_IP, requestedIP);
            }
        } catch (NumberFormatException e) {  // Если возникла ошибка при парсинге IP
            sendPacket(clientSocket, clientMAC, SERVER_MAC, ERROR,
                    "0.0.0.0", SERVER_IP, "Неверный формат IP");
        }
    }

    /**
     * Находит и возвращает свободный IP адрес из пула.
     * При успешном нахождении помечает этот IP как занятый.
     *
     * @return Свободный IP-адрес или null, если все адреса заняты
     */
    private static String getFreeIP() {
        synchronized (ipPool) {
            // Проходим по всему диапазону
            for (int i = IP_POOL_START; i <= IP_POOL_END; i++) {
                if (!ipPool[i]) {  // Если IP адрес свободен (значение false)
                    ipPool[i] = true;  // Помечаем IP как занятый
                    return "192.168.1." + i;  // Формируем и возвращаем полный IP адрес
                }
            }
        }
        return null;
    }

    /**
     * Преобразует массив из 4 байт в целое число
     *
     * @param bytes Массив из 4 байт
     * @return Целое число, представленное этими байтами
     */
    private static int byteArrayToInt(byte[] bytes) {
        // Преобразуем 4 байта в int, учитывая порядок байт
        return ((bytes[0] & 0xFF) << 24) |  // Первый байт сдвигаем на 24 бита - старший байт
                ((bytes[1] & 0xFF) << 16) |  // Второй байт сдвигаем на 16 бит
                ((bytes[2] & 0xFF) << 8) |   // Третий байт сдвигаем на 8 бит
                (bytes[3] & 0xFF);           // Четвертый байт - младший байт
    }

    /**
     * Преобразует целое число в массив из 4 байт.
     *
     * @param value Целое число
     * @return Массив из 4 байт, представляющий это число
     */
    private static byte[] intToByteArray(int value) {
        // Преобразуем int в массив из 4 байт
        return new byte[] {
                (byte)(value >>> 24),        // сдвиг на 24 бита вправо
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
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

            byte[] dataLengthBytes = intToByteArray(dataBytes.length);  // Преобразуем длину данных в байты

            // Записываем все поля  в выходной поток
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
     *
     * @param s Исходная строка
     * @param n Требуемая длина
     * @return Строка нужной длины, дополненная пробелами справа
     */
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);  // Используем  для выравнивания по левому краю
    }
}