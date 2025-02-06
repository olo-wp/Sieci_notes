Notatki do Egzaminu
======
1 Warstwy
------

Realizacja ramki ethernet wysyłającej IPv4 zawierający fragment strumienia TCP podczas pobierania pliku z serwera HTTP:
- Preambuła i SFD 8 bajt
- Nagłówek Ethernet
- Nagłówek IPv4
- Nagłówek TCP
- Dane
- CRC, kontrola błędów

Różnica między ISO-OSI a TCP-IP

| ISO-OSI          | TCP-IP          |
|------------------|-----------------|
| Warstwa fizyczna | Dosępu do Sieci |
| Łącza danych     | ^^^^            |
| Sieci            | Internetu       |
| Transportu       | Transportu      |
| Sesji            | Aplikacji       |
| prezentacji      | ^^^^            |
| Aplikacji        | ^^^^            |

Konsekwencje warstwowej budowy:

Zalety:
+ Modularność
+ Abstrakcja
+ Optymalizacja
Wady:
- Redundancja

Problemy rozwiązywane wielowarstwowo
- Kontrola błędów: FCS w ethernet, sumy kontrolne w TCP
- Bezpieczeństwo: W warstwie aplikacji HTTPS, w sieci IPsec
- Kolejkowanie: Kontrola przepływu TCP w warstwie transportu, Kolejkowanie w ruterze (warstwa sieci)

Interakcje między warstwami:
IP - wskazuje na protokuł transportu
TCP - ma porty identyfikujące aplikacje korzystające z sieci

Ethernet
----
#### Rozwój Ethernet

| 10-Base5 | 10-Base2 | Fast | Gigabit | Swiatlowod |
| ---- | ---- | ---- | ---- | ----| 
 | 10mbs gruby kabel | cienki kabel | 100Mbs skretka | 1Gbs |  |

Rozwój struktury: Kabel koncentryczny -> gwiazda hub -> gwiazda switch

#### Ramka Ethernet

| Preambula | start | MAC odbiorca | MAC source | Ether-typ | Payload | CRC |
| ---- | ---- | ---- | ---- | ---- | ----| ---- |
|7|1|6|6|2|46-1500|4|

Minimalny size: 64
Max size: 1518
Licząc size nie liczymi preambuly i startu

#### Metody przesyłania

~~kabel koncentryczny~~ to jest stare i już się nie używa
Skrętka
Światłowód
Fale radiowe (wifi)

Kodowania:
10-Base -- Manchaster
1000-Base --  PAM-S
10G-Base -- NRZ

#### Switched Ethernet

Różni się tym że używa switcha zamiast hubów i magistrali co pozwala na:
- Brak kolizyjności
- Dedykowana przepustowość dla każdego urządzenia
- Pełny dupleks -> możliwość jednoczesnego odbioru i przesyłu
- Zamiast wysyłąć daną informacje do wszystkich, tak jak było to w hubach, wysyłamy tlyko do właściwego odbiorcy

Switche też mają strukturę gwiazdy tak jak huby, ale są dużo optymalniejsze

#### Zmiany w algorytmach współdzielnia

- Huby poprawiły problem z kolizjami
- Switche polepszyły skalowanie
- ARP służy do tego aby pozyskać MAC posiadając adres IP
- Spanning tree protocol -> wykrywa cykle i deaktywuje nadmiarowe ścieżki

#### Cykle

Cykle w sieci mogą prowadzić do broadcast storm (pakiety krążą w nieskończoność),
bo w Ethernet nie ma TTL (takie coś co po iluś przejściach pakietu usuwa pakiet)

#### VLAN
VLAN pozwala na podzielenie jednej fizycznej sieci na wiele segmentów logicznych. Użądzenie w różnych VLAN nie mogą się między sobą komunikować bezpośrednio

Plusy:
- bezpieczeństwo
- organizacja
- efektywność

3 WIFI 
----

#### Połąćzenie klienta z AP
1. Klient skanuje szukając sieci
    - Skanowanie pasywne, czekamy aż zobaczymy 
    - Skanowanie aktywne, wysyłami prośbę do rutera
2. Asocjacja z AP -> w tym momencie jesteśmy połączenie z AP
3. Uwierzytelnienie
    - open acces -> brak hasła
    - ~~WED~~ jakieś stare gówno co się go nie używa
    - WPA2 / WPA3 ma hasło więcej niżej

#### Rola AP w algorytmach wspołdzielenia komunikacji
na pewno unika kolizje - Collision avoidance

#### Niekorzystamy z klasycznego Carrier Sense bo:
- Problem ukrytego węzła, nie wszystkie urządzenia słyszą siebie nawzajem
- Fale są bardziej podatne na zakłócenia niż kabel
- Stosuje się CSMA/CA, zamiast CSMA/CD , zamiast detektować kolizje staramy się ich uniknąć

#### WPA2/WPA3

WPA2
1. 4Way-handshake
- AP wysyła nonce (losowa liczba)
- klient generuje PTK (Pairwise Transient key) - klucz szyfrujący z hasła i nonce
- klient odsyła nonce
- AP i klient finalnie wyliczają ten sam PTK
- Dane są szyfrowane w 128 bit

W WPA3 nie generujemy PTK za pomocą hasła tlyko czegoś tam innego i przez to jest lepszy na brute force + szyfrowanie jest 198 bit w WPA3

#### Łączenie WIFI i Ethernet

1. Mostkowanie, AP pełni funkcje mostu między WIFI do Ethernety
2. NAT - przypisywanie prywatnego IP urządzenie w sieci WIFI, które będą się łączyć z ethernet
3. VLAN

4 IP
----
#### Tablice trasowanie

|Docelowa sieć|
|----|
|Maska podsieci|
|Bramka |
|Interfejs|
|Metryka|

Jak to działa?
1. ruter sprawdza docelowe IP
2. Porównuje go ze wpisami z tablicy stosując maskę podsieci
3. Wylicza najkorzystniejszą trasę

#### Dlaczego to działa

1. IP są przechowywane hierarchicznie
2. Protokoły trasowanie działają dynamicznie, więc jak zmienia się sieć to wyliczają nową najlepszą trasę
3. Jak nie ma zdefiniowanej trasy w danym ruterze, to przekazujemy do domyślnej bramki, gdzie są trasy wszędzie
4. Można ręcznie definiować trasy

#### Distance Vector i Link-State

|Distance-Vector| Link-State |
|---- | --- |
|Każdy ruter wysyła okresowo do sąsiada info o metryce do poszczególnych sieci | Każdy ruter buduje sobie całą mapę sieci |
|Metryka : liczba przeskoków | Metryka: może być bardziej skomplikowana, np zawierać przepustowość i opóźnienia |
|Wolna zbieżność, podatność na pętle | Szybka zbieżność, brak pętli |
|Uzywana w małych sieciach, bo prosta w implementacji | używana w dużych bo trudna w implementacji |

#### Porty
Nie kązdy ruch IP ma porty, są one związane tylko z warstwą transportową (TCP/UDP)

#### Przekazywanie pakietów IP do aplikacji
1. karta sieciowa dostaje pakiet i przekazuje go do sterowników sieciowych i do jądra
2. Jądro sprawdza nagłówek wskazujący na to która aplikacja go potrzebuje
3. Wysyła go do odpowiedniej aplikacji

#### IP-SEC

- Authentication Header -> chroni przed modyfikacją danych
- IKE Internet key exchange -> wymiana szyfrowanych kluczy
- ESP Encapsulating Security Protocol -> szyfruje dane, chroni przed przeczytaniem ich z zewnątrz i chyba też przed modyfikacją

5 UDP
----

#### DHCP używa UDP bo:

- UDP jest lżejszse i szybsze niż TCP (brak handshake)
- DHCP nie potrzebuje niezawodnośći
- kom. broadcast ??

#### DNS używa UDP bo:

- Zapytania i odp DNS są krótkie i mieszczą się w jednym datagramie
- UDP jest szybkie
- DNS jest bezstanowy i UDP do tego pasuje

#### TCP a UDP

| TCP | UDP |
| --- | --- |
|Połączeniowy (handshake) | bezpołączeniowy (brak konieczności handshake) |
| gwaracncja dostaeczenia i poprawnej kolejności | brak |
|kontrola przepływu | brak |
|niezawodność | brak |
| Wysoki narzut | Niski narzut |
|wolniejsze | szybsze |

#### wiele klientów w UDP
Łatwo to się implementuje bo nie potrzeba wielu wątków, UDP otrzymując z recvfrom() dostaje też adres, na który ma odesłać informacej i odsyla je używając sendto()

#### API do obsługi UDP w python

moduł socket
funkcje: 
- sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM
- server_adress = (host, port)
- sock.bind(server_adress)
- data, client_address = sock.recvfrom(4096) odbieranie 4096 bajtów
- mes - "hi" sock.sendto(mes.encode(), client_adress)
- sock.close()

to jest zrozumiałe samo przez sie

6 TCP
-----

#### Nawiązywanie połączenia z TCP
To się nazywa 3-way handshake

1. SYN: klient wysyła segment z flagą SYN ustawioną na jeden i losowy numer sekwencji
2. SYN-ACK: serwer odsyła segment z SYN = 1, ACK = 1, i swoim losowym numerem sekwencji oraz odsyła numer który dostał powiększony o 1
3. ACK: klient odsyła numer od serwera powiększony o jeden i flage ACK

#### Technika sliding window

Technika Sliding Window (przesuwającego się okna) jest używana w TCP do efektywnego zarządzania przepływem danych i kontroli przeciążeń.

1. Okno transmijsi: Okno określa ile bajtów można wysłać bez oczekiwania na potwierdzenie (ACK), jest to dynamicznie dostosowywane
2. Gdy nadawca dostanie ACK dla części danych, to może przesunąć sobie okno do przodu, co umożliwia wysłanie większej ilości danych
3. Zalety:
 - większa efektywność wykorzystania łącza
 - umożliwia jednoczesne wysyłanie i potwierdzanie danych

#### Sterowanie prędkośći
W TCP jest pare mechanizmów do tego:

1. Slow start: na początku okno jest małe (1 segment), z każdym ack się podwaja
2. Congestion avoidance: jak okno osiągnie jakiś próg, wzrost staje się liniowy (okno zwiększa się o 1 co każdą turę czasu)
3. Fast Retransmit: Gdy nadawca otrzyma 3 razy ACK dla tego samego segmentu, oznacza to że segment jest zgubiony i nadawaca od razu wysyła go ponownie
4. Fast Recovery: Po wykryciu utraty pakietu nadawca zmniejsza okno dwukrotnie i przechodzi do Congestion Avoidance (wzrost liniowy)

#### Typy TCP

1. TCP Tahoe:
- Wykrywa utratę pakietów poprzez timeout lub duplikat ACK.
- W przypadku utraty pakietu przechodzi do fazy Slow Start.
- Brak mechanizmu Fast Recovery.
2. TCP Reno:
- Rozwinięcie TCP Tahoe z dodanym mechanizmem Fast Recovery.
- W przypadku duplikatów ACK przechodzi do Fast Recovery zamiast Slow Start.
- Lepsza wydajność w przypadku pojedynczych utrat pakietów.
3. TCP Vegas:
- Wykrywa przeciążenie na podstawie opóźnień (RTT) zamiast utraty pakietów.
- Dostosowuje rozmiar okna w zależności od różnicy między oczekiwanym a rzeczywistym czasem dostarczenia.
- Mniej agresywny niż Tahoe i Reno, co prowadzi do lepszego wykorzystania łącza.

#### API dla TCP w pytonie
 
```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 12345)
sock.bind(server_address)

sock.listen(5)  # 5 to maksymalna liczba oczekujących połączeń

client_socket, client_address = sock.accept()
print(f"Połączenie z {client_address}")

sock.connect(server_address)

message = "Witaj, serwerze!"
sock.send(message.encode())

data = sock.recv(4096)  # 4096 to rozmiar bufora
print(f"Odebrano: {data.decode()}")

sock.close()
```

^^^^ to są przykłady jakiś funkcji, da się domyśleć co one robią.


7 DNS
------

#### Jak to działa i co to jest
System DNS (Domain Name System) to hierarchiczna, rozproszona baza danych, która mapuje przyjazne dla człowieka nazwy domen (np. www.example.com) na adresy IP (np. 93.184.216.34). 

1. Hierarchia domen
- root: .
- najwyższy poziom (TLD): .com, .org, .pl
- poziom nizej: example.com , edu.pl
- Poziomy sobie schodzą niżej np 4 poziom to .tcs.uj.edu.pl
2. Serwey DNS
- Root servers - przechowują informacje o serwerach TLD
- TLD serwers - przechowują info o serwerach drugiego poziomu
- Authoritative servers: Serwery autorytatywne, które przechowują faktyczne rekordy DNS dla domen.
3. Co jest w rekodzie DNS?
- A (mapping na IPv4)
- AAAA (mapping na IPv6)
- CNAME (alias dla nazwy domeny)
- NS wskazuje serwer nazw dla domeny
- i inne

#### Zasady rejstracji w DNS

- aby dodać wpisy do DNS, trzeba zarejstrować domene u rejstratora, on jest odpowiedzialny za rejstracje rekordów w TLD
- Trzeba skonfigurować serwer nazw (NS) dla domeny, przechowuje on rekordy DNS
- zmiany zajmują do kilku godzin

#### Algorytm odczytu wpisów

- klient wysyła zapytanie do resolvera DNS
- Resolver robi rekurencyjne zapytanie zaczynając od roota czyli .pl -> .edu.pl -> .uj.edu.pl -> tcs.uj.edu.pl
- resolver zwraca IP do klienta

#### Automatyczne i przeźroczyste DNS-y
Automatyczne wykorzystanie:
- Większość aplikacji korzysta z DNS automatycznie, np. przeglądarki internetowe, klienty pocztowe.
- System operacyjny zapewnia resolver DNS, który obsługuje zapytania w tle.
Przeźroczyste dla programisty:
- Programiści zwykle nie muszą ręcznie zarządzać DNS.
- Biblioteki sieciowe (np. w Pythonie, Java) automatycznie tłumaczą nazwy domen na adresy IP przy użyciu systemowego resolvera.

np w pytonie:
```python
import socket
ip_address = socket.gethostbyname('www.example.com')
print(ip_address)
```

#### DNSSEC

1. Podpisy cyfrowe:
- Rekordy DNS są podpisywane cyfrowo przy użyciu kluczy prywatnych.
- Klucze publiczne są dystrybuowane w rekordach DNSKEY.
2. Łańcuch zaufania:
- Każdy poziom hierarchii DNS (korzeń, TLD, domena) podpisuje swoje rekordy.
- Resolver weryfikuje podpisy, korzystając z kluczy publicznych.
3. Rekordy DNSSEC:
- RRSIG: Podpis cyfrowy dla zestawu rekordów.
- DNSKEY: Zawiera klucze publiczne.
- DS: Delegation Signer – rekord używany do weryfikacji łańcucha zaufania.
4. Zapobieganie atakom:
- Spoofing: DNSSEC zapobiega fałszowaniu odpowiedzi DNS.
- Cache poisoning: Podpisane rekordy uniemożliwiają wstrzykiwanie fałszywych danych do cache'u resolvera.
5. Ograniczenia:
- DNSSEC nie szyfruje danych, więc nie chroni przed podsłuchem.
- Wymaga wsparcia od rejestratorów, serwerów nazw i resolverów.

8 HTTP
-----
#### zawartość strumienia TCP
podczas komunikacji z HTTP strumień zawiera nagłówki oraz dane

- Nagłówek TCP
  1. Port źródłowy i docelowy w HTTP 80, w HTTPS 443
  2. Numery sekwencji i potwierdzenia: Używane do zarządzania przepływem danych i zapewnienia niezawodności.
  3. Flagi SYN, ACK, FIN do nawiązywania i zakończenia połączenia
- Nagłówek HTTP
  1. Żądanie(Request): 
     * metoda: GET, POST, PUT, DELETE itp
     * Url - ścieżka do zasobu
     * wersja HTTP
     * Nagłówki: np. Host, User-Agent, Accept.
  2. Odpowiedź(Response):
      * Status (200 - OK , 404 Not Fount)
      * Nagłówki: np. Content-Type, Content-Length, Server.
- Treść wiadomości
  1. W przypadku żądania POST, treść zawiera dane przesłane do serwera.
  2. W przypadku odpowiedzi, treść zawiera żądany zasób (np. HTML, obraz).

#### Różnice w wykorzystaniu TCP w różnych wersjach

Różnice w wykorzystaniu połączenia TCP w różnych wersjach HTTP

1. HTTP/1.0:
   - Połączenie TCP: Każde żądanie/odpowiedź wymaga nowego połączenia TCP.
   - Wydajność: Niska, ze względu na narzut związany z nawiązywaniem i zamykaniem połączeń.
2. HTTP/1.1:
   - Persistent Connections: Wiele żądań/odpowiedzi może być przesyłanych przez jedno połączenie TCP.
   - Pipelining: Żądania mogą być wysyłane jedno po drugim bez czekania na odpowiedzi (rzadko używane).
   - Wydajność: Lepsza niż HTTP/1.0, ale nadal występuje problem z blokowaniem (head-of-line blocking).
3. HTTP/2:
   - Multiplexing: Wiele żądań/odpowiedzi może być przesyłanych równolegle przez jedno połączenie TCP.
   - Binary Framing: Dane są przesyłane w postaci binarnych ramek, co zwiększa wydajność.
   - Wydajność: Znacznie lepsza niż HTTP/1.1, eliminuje problem blokowania.
4. HTTP/3:
   - QUIC: Zamiast TCP, używa protokołu QUIC opartego na UDP.
   - Wydajność: Lepsza obsługa strat pakietów i szybsze nawiązywanie połączeń.
 

#### Powody i konsekwencje różnic

- Powody:
    - Wydajność: Każda nowa wersja HTTP wprowadza mechanizmy poprawiające wydajność.
    - Bezpieczeństwo: Nowe wersje wprowadzają lepsze mechanizmy bezpieczeństwa.
    - Kompleksowość: Rosnące wymagania aplikacji webowych wymuszają rozwój protokołu.
- Konsekwencje:
  - HTTP/1.1: Poprawa wydajności, ale nadal ograniczenia związane z blokowaniem.
  - HTTP/2: Znaczna poprawa wydajności, ale zależność od TCP.
  - HTTP/3: Eliminacja problemów TCP poprzez użycie QUIC.

#### Mechanizmy bezpieczeństwa w HTTP

- HTTPS:
HTTP over TLS/SSL, zapewnia szyfrowanie danych.
Chroni przed podsłuchem i manipulacją danych.
- Strict Transport Security (HSTS):
Wymusza użycie HTTPS przez przeglądarkę.
Zapobiega atakom typu downgrade.
- Content Security Policy (CSP):
Ogranicza źródła, z których można ładować zasoby (skrypty, style itp.).
Chroni przed atakami XSS.
- Cookies z flagą Secure i HttpOnly:
Secure: Cookies są przesyłane tylko przez HTTPS.
HttpOnly: Blokuje dostęp do cookies przez JavaScript.

#### Wykorzystanie HTTP do kontynuowania pobierania częściowo pobranego pliku

1. Nagłówek Range:
Klient może wysłać żądanie z nagłówkiem Range, aby pobrać tylko część pliku.
Przykład: Range: bytes=500-999 pobiera bajty od 500 do 999.
2. Odpowiedź serwera:
Serwer odpowiada kodem 206 Partial Content i zwraca żądaną część pliku.
3. Nagłówek Content-Range wskazuje zakres bajtów (np. Content-Range: bytes 500-999/2000).
4. Kontynuacja pobierania:
Klient może wysłać kolejne żądania z różnymi zakresami, aby pobrać cały plik.

#### Dynamiczne generowanie treści przez http

1. CGI (Common Gateway Interface):
Pozwala na uruchamianie zewnętrznych programów w odpowiedzi na żądania HTTP.
Przykład: Skrypty Perl, Python.
2. FastCGI:
Ulepszona wersja CGI, która utrzymuje procesy w pamięci, zwiększając wydajność.
3. Serwery aplikacji:
np. Apache Tomcat, Node.js, które obsługują dynamiczne treści w czasie rzeczywistym.
4. Frameworki webowe:
np. Django (Python), Ruby on Rails, które ułatwiają tworzenie dynamicznych aplikacji webowych.
5. SSI (Server Side Includes):
Pozwala na wstawianie dynamicznych treści do statycznych stron HTML.
6. API:
Serwery mogą udostępniać API, które zwracają dynamiczne dane w formacie JSON lub XML.

9 SSL
----

#### gwarancje bezpieczeństwa SSL


SSL (Secure Sockets Layer) i jego następca TLS (Transport Layer Security) zapewniają następujące gwarancje bezpieczeństwa:

1. Poufność:
Szyfrowanie danych przesyłanych między klientem a serwerem, co uniemożliwia podsłuchanie.
2. Integralność:
Mechanizmy kontroli integralności (np. HMAC) zapewniają, że dane nie zostały zmienione podczas transmisji.
3. Autentykacja:
Uwierzytelnienie serwera (a czasem również klienta) za pomocą certyfikatów cyfrowych.
Klient może zweryfikować, czy łączy się z prawdziwym serwerem, a nie z fałszywym.
4. Ochrona przed atakami:
Zapobieganie atakom typu man-in-the-middle (MITM), replay attacks i innym formom manipulacji.

#### Wymagania dla aplikacji korzystających z SSL/TLS

1. Biblioteka SSL/TLS:
Aplikacja musi korzystać z biblioteki obsługującej SSL/TLS, np. OpenSSL, GnuTLS.
2. Certyfikaty:
   - Serwer musi posiadać certyfikat cyfrowy wystawiony przez zaufany urząd certyfikacji (CA).
   - Klient może również wymagać certyfikatu (w przypadku wzajemnego uwierzytelniania).
3. Konfiguracja:
Należy skonfigurować serwer do obsługi SSL/TLS, w tym wybrać odpowiednie protokoły i szyfry.
4. Porty:
SSL/TLS zwykle działa na dedykowanych portach, np. 443 dla HTTPS.
5. Obsługa błędów:
Aplikacja musi obsługiwać błędy związane z certyfikatami (np. wygasłe certyfikaty, nieznane CA).

#### Kryptografia klucza symetrycznego i publicznego

1. Kryptografia klucza publicznego:
   - Używana podczas nawiązywania połączenia (handshake) do wymiany kluczy i uwierzytelnienia.
   - Klucz publiczny serwera jest zawarty w certyfikacie, a klucz prywatny jest przechowywany na serwerze.
   - Klient używa klucza publicznego serwera do zaszyfrowania klucza sesji, który jest następnie przesyłany do serwera.
2. Kryptografia klucza symetrycznego:
   - Używana do szyfrowania danych podczas transmisji.
   - Klucz sesji, uzgodniony podczas handshake, jest używany do szyfrowania i deszyfrowania danych.

#### Etapy nawiązywania połączenia SSL/TLS

1. Hello:
   - Klient wysyła wiadomość ClientHello z informacjami o obsługiwanych wersjach SSL/TLS, szyfrach i losowej wartości (nonce).
   - Serwer odpowiada wiadomością ServerHello, wybierając wersję protokołu, szyfr i wysyłając własną wartość nonce.
2. Wymiana certyfikatów:
Serwer wysyła swój certyfikat i, jeśli wymagane, żąda certyfikatu od klienta.
3. Wymiana kluczy:
   - Klient generuje klucz sesji, szyfruje go kluczem publicznym serwera i wysyła do serwera.
   - Serwer odszyfrowuje klucz sesji swoim kluczem prywatnym.
4. Zakończenie handshake:
Obie strony wymieniają wiadomości Finished, które są zaszyfrowane kluczem sesji, aby potwierdzić, że handshake zakończył się sukcesem.
5. Komunikacja:
Po zakończeniu handshake, dane są przesyłane w sposób zaszyfrowany przy użyciu klucza sesji.

#### Schemat certyfikacji kluczy w SSL/TLS

1. Certyfikaty cyfrowe:
Certyfikat zawiera klucz publiczny serwera, informacje o serwerze (np. nazwę domeny) oraz podpis cyfrowy wystawcy (CA).
2. Urzędy certyfikacji (CA):
   - CA to zaufane organizacje, które wystawiają i podpisują certyfikaty.
   - Przykłady: Let's Encrypt, DigiCert, GlobalSign.
3. Łańcuch zaufania:
   - Certyfikat serwera jest podpisany przez CA.
   - Klient posiada listę zaufanych CA i weryfikuje podpis certyfikatu serwera.
4. Certyfikaty klienta:
W przypadku wzajemnego uwierzytelniania, klient również posiada certyfikat, który jest weryfikowany przez serwer.

Są trzy stopnie certyfikacji:
1. Root CA (Główny Urząd Certyfikacji)
   - Rola: Root CA to najwyższy poziom hierarchii. Jest źródłem zaufania dla całego systemu PKI.
   - Certyfikat: Root CA posiada certyfikat samopodpisany (self-signed), co oznacza, że sam siebie uwierzytelnia.
   - Bezpieczeństwo: Klucz prywatny Root CA jest przechowywany w najwyższym stopniu bezpieczeństwa (np. offline, w sejfie).
   - Zastosowanie: Root CA nie wystawia certyfikatów dla użytkowników końcowych, ale podpisuje certyfikaty pośrednich CA (Intermediate CA).
2. Intermediate CA (Pośredni Urząd Certyfikacji)
   - Rola: Intermediate CA działa jako pośrednik między Root CA a użytkownikami końcowymi.
   - Certyfikat: Intermediate CA posiada certyfikat podpisany przez Root CA.
   - Zastosowanie: Intermediate CA wystawia certyfikaty dla użytkowników końcowych (serwerów, klientów) lub dla innych pośrednich CA.
   - Bezpieczeństwo: Klucz prywatny Intermediate CA jest również chroniony, ale może być przechowywany w bardziej dostępnym środowisku niż klucz Root CA.
3. End-Entity CA (Urząd Certyfikacji Użytkowników Końcowych)
   - Rola: Ten poziom wystawia certyfikaty dla użytkowników końcowych, takich jak serwery, urządzenia lub osoby.
   -  Certyfikat: Certyfikaty użytkowników końcowych są podpisane przez Intermediate CA.
   - Zastosowanie: Certyfikaty te są używane do uwierzytelniania w aplikacjach, takich jak HTTPS, VPN, podpisywanie dokumentów itp.


#### pyton API do ssl

przykładowy prosty serwer ssl:
```python
import socket
import ssl

def start_ssl_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 443))
    sock.listen(5)

    print("Serwer SSL nasłuchuje na localhost:443...")
    while True:
        client_sock, addr = sock.accept()
        ssl_sock = context.wrap_socket(client_sock, server_side=True)
        print(f"Połączenie z {addr}")
        data = ssl_sock.recv(4096)
        print(f"Odebrano: {data.decode()}")
        ssl_sock.send(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, SSL!")
        ssl_sock.close()

if __name__ == "__main__":
    start_ssl_server()
```

10 Chord
-----
Distributed Hash Table (DHT) to rozproszona struktura danych, która umożliwia przechowywanie i wyszukiwanie par klucz-wartość w sieci peer-to-peer (P2P). DHT jest używany do budowy skalowalnych i odpornych na awarie systemów rozproszonych.

#### Główne cechy DHT
1. Rozproszenie:
   - Dane są rozproszone między wiele węzłów (komputerów) w sieci.
   - Każdy węzeł przechowuje tylko część danych.
2. Skalowalność:
   - System może obsługiwać dużą liczbę węzłów i danych.
3. Tolerancja na awarie:
   - DHT jest odporny na awarie pojedynczych węzłów, ponieważ dane są replikowane.
4. Efektywność:
   - Wyszukiwanie danych jest zwykle wykonywane w czasie logarytmicznym względem liczby węzłów.

#### Przykłady zastosowania DHT w systemach informatycznych

1. Sieci P2P:
   - BitTorrent: DHT jest używany do wyszukiwania peerów bez centralnego tracker'a.
   - IPFS: DHT jest używany do rozproszonego przechowywania i wyszukiwania plików.
2. Rozproszone bazy danych:
   - Cassandra: DHT jest używany do dystrybucji danych między węzłami.
   - Riak: DHT jest używany do przechowywania i wyszukiwania danych w rozproszonym systemie.
3. Systemy nazw:
   - Chord: DHT jest używany do mapowania nazw na adresy IP w rozproszonych systemach.

#### Logika działania Chord

1. Przestrzeń kluczy
   - Klucze i węzły są mapowane na pierścień o rozmiarze 2^m (m to liczba bitów w identyfikatorze)
   - Każdy węzeł ma unikalny hash
2. Finger Table:
   - Każdy węzeł utrzymuje tablicę (finger table) zawierającą informacje o innych węzłach.
   - Tablica umożliwia wyszukiwanie węzłów w O(log N)
3. Wyszukiwanie klucza:
   - Węzeł rozpoczyna wyszukiwanie od sprawdzenia, czy klucz znajduje się w jego zakresie.
   - Jeśli nie, przekazuje zapytanie do węzła, który jest bliżej docelowego klucza (na podstawie finger table).
4. Przechowywanie danych:
   - Każdy klucz jest przypisany do węzła, którego identyfikator jest równy lub następny po haśle klucza.

#### Dodawanie i usuwanie węzła w chord

1. Dodawanie węzła:
   - Nowy węzeł oblicza swój identyfikator (hash) i dołącza do pierścienia.
   - Węzeł przejmuje odpowiedzialność za klucze, które teraz znajdują się w jego zakresie.
   - Finger table nowego węzła jest aktualizowana, a sąsiednie węzły również aktualizują swoje tablice.
   - działa to w O(log N)
2. Usuwanie węzła:
   - Węzeł opuszcza pierścień, przekazując odpowiedzialność za swoje klucze następnemu węzłowi.
   - Sąsiednie węzły aktualizują swoje finger table.
   - działa to w O(log n)

#### Podatność na wrogie przejęcie

1. Ataki typu Sybil:
   - Atakujący tworzy wiele fałszywych węzłów, aby przejąć kontrolę nad częścią pierścienia.
   - Może to prowadzić do manipulacji danymi lub ich utraty.
2. Ataki typu Eclipse:
   - Atakujący przejmuje kontrolę nad węzłami, które są kluczowe dla danego węzła (np. sąsiedzi w pierścieniu).
   - Może to prowadzić do izolacji węzła i manipulacji jego danymi.
3. Mechanizmy obrony:
   - Uwierzytelnianie węzłów: Wymaganie certyfikatów lub innych form uwierzytelnienia.
   - Replikacja danych: Przechowywanie kopii danych na wielu węzłach, aby zmniejszyć ryzyko utraty.
   - Monitorowanie: Regularne sprawdzanie integralności danych i węzłów.





