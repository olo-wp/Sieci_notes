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


12 Fizyczne zagadnienia komunikacji
----

#### Ile metrów ma bit

Ogólnie to pytanie nie ma sensu, ale jakby się uprzeć to można tak:
- Odległość = Prędkość propagacji / częstotliwość transmisji
- Czyli na przykład w światłowodzie odl = 2 * 10^8 / 10^9 = 0.2 m

#### Ile czasu zajmuje jeden bit

Jeśli mamy przepustowość R bitów na sekundę to t = 1/R

#### Twierdzenie Shannona i Nyquista

- Twierdzenie Shannona: transmisji danych w kanale **bez szumu** jest ograniczona przez szerokość pasma
  B i liczbę poziomów sygnału M
- C = 2B * log_2(M)

- Twierdzenie Nyquista: transmisji danych w kanale **z szumem** jest ograniczona przez szerokość pasma
  B i stosunek sygnału do szumu SNR
- C = B * log_2(1+SNR)

#### Fizyczne aspekty bezpieczeństwa komunikacji

1. Podsłuch:
    - Fizyczne przechwycenie sygnału (np. przez podłączenie do kabla).
    - Zabezpieczenia: Szyfrowanie danych, użycie światłowodów (trudniejsze do podsłuchu).
2. Zakłócenia:
    - Celowe lub przypadkowe zakłócenie sygnału (np. ataki typu jamming).
    - Zabezpieczenia: Użycie odpornych na zakłócenia technologii (np. rozpraszanie widma).
3. Ataki typu side-channel:
    - Wykorzystanie fizycznych właściwości systemu (np. czas reakcji, zużycie energii).
    - Zabezpieczenia: Maskowanie sygnałów, izolacja fizyczna.

#### Dlaczego dzielimy komunikację na wiadomości o ograniczonym rozmiarze?

1. Efektywność:
    - Mniejsze wiadomości są łatwiejsze do zarządzania i retransmisji w przypadku błędów.
2. Kontrola przepływu:
    - Dzielenie na mniejsze jednostki pozwala na lepsze zarządzanie przepustowością i unikanie przeciążeń.
3. Fragmentacja:
    - Sieci mają różne MTU (Maximum Transmission Unit), co wymaga dzielenia dużych wiadomości.

###### Mechanizm fragmentacji IP

- MTU: Maksymalny rozmiar ramki, który może być przesłany przez sieć.
- Fragmentacja: Jeśli pakiet IP jest większy niż MTU, jest dzielony na mniejsze fragmenty.
- Reasemblacja: Fragmenty są ponownie składane przez odbiorcę.
- Problemy: Fragmentacja może prowadzić do utraty wydajności i zwiększenia ryzyka utraty pakietów.

###### Znaczenie rozmiaru wiadomości w kryptografii

1. Blokowe szyfry:
    - Szyfry blokowe (np. AES) działają na danych o stałym rozmiarze (np. 128 bitów).
        - Wiadomości muszą być podzielone na bloki przed zaszyfrowaniem.
2. Podpisy cyfrowe:
    - Podpisy są generowane dla skrótów wiadomości (hash), co wymaga podziału dużych wiadomości.
3. Bezpieczeństwo:
    - Zbyt duże wiadomości mogą być podatne na ataki (np. ataki typu padding oracle).

###### Wpływ rozmiaru wiadomości na protokół TCP

1. Segmentacja:
    - TCP dzieli dane na segmenty o rozmiarze MSS (Maximum Segment Size).
    - MSS jest zwykle mniejszy niż MTU, aby uniknąć fragmentacji IP.
2. Kontrola przepływu:
    - TCP używa mechanizmów okienkowych, które zależą od rozmiaru segmentów.
3. Retransmisja:
    - W przypadku utraty segmentu, tylko ten segment jest retransmitowany, co zwiększa efektywność.
4. Opóźnienie:
    - Zbyt małe segmenty mogą zwiększyć narzut związany z nagłówkami, podczas gdy zbyt duże mogą prowadzić do opóźnień w przypadku błędów.

##### Po co te trzy rzeczy

- Fragmentacja do przesyłania informacji niemieszczących się w ramce
- Wielkość wiadomości jest ważna, bo algorytmy szyfrujące działają często na określonej wielkości danych, na przykład wielokrotności 128 dla AES
- Podpisy są generowane dla stałej wielkości skrótów (256 bit dla SHA-256)
- Zbyt duże wiadmości są podatne na ataki
- Trzecie jest ważne, aby TCP było efektywne


13 Błędy Transmisji
-----
#### Podaj przykłady technologii sieciowych wykrywających i korygujących błędy komunikacji oraz jakie algorytmy korzystaja.

1. Ethernet
    - CRC-32: Jeśli suma kontrolna nie zgadza się po stronie odbiorcy to ramka jest odrzucana
    - algorytm nazywa się tak samo: CRC-32
2. Wi-Fi
    - Forward error connection (FEC), Koryguje błędy podczas transmisji, dodaje bity parzystości co pozwala na korekcje błędów bez retransmisji
    - Korzysta z kodowania Hamminga, Reed-solomon
3. TCP
    - TCP używa ACK i sum kontrolnych do wykrywania błędów oraz retransmisji
    - Algorytm: Suma kontrolna, potwierdzenia (ACK) i retransmisja.

#### Jak protokół TCP wykrywa błędy transmisji i jak na nie reaguje?

1. Wykrywanie błędów:
    - Suma kontrolna: Każdy segment TCP zawiera sumę kontrolną, która jest obliczana na podstawie danych. Jeśli suma kontrolna nie zgadza się po stronie odbiorczej, segment jest uznawany za uszkodzony.
    - Sekwencja numerów: TCP używa numerów sekwencji i potwierdzeń, aby śledzić, które segmenty zostały odebrane poprawnie.
2. Reakcja na błędy:
    - Retransmisja: Jeśli odbiorca nie potwierdzi odebrania segmentu w określonym czasie (timeout), nadawca retransmuje segment.
    - Potwierdzenia selektywne (SACK): TCP może używać potwierdzeń selektywnych, aby wskazać, które segmenty zostały odebrane poprawnie, a które wymagają retransmisji.

#### Błędy w UDP

- Zła kolejnośc
- Brak niektórych pakietów
- Zduplikowane pakiety
- Uszkodzone pakiety

#### Ile bitów trzeba przesłać, żeby przekazać 32 bitów wiadomości z możli- wością skorygowania do 4 bitów błędu.

- Kodem Hamminga:
    - liczba bitów parzystości musi spełniać 2^r >= 32 + r +1
    - r = 6
    - czyli trzeba 32 + 6 = 38
- Kodem BCH jakies 40-45

#### Jakie błędy transmisji wpływają na mechanizmy bezpieczeństwa

1. Błędy transmisji mogą naruszyć integralność danych, co może prowadzić do nieprawidłowego działania mechanizmów bezpieczeństwa (np. podpisy cyfrowe, sumy kontrolne).
2. Uszkodzone dane mogą być trudne do odszyfrowania, co może prowadzić do utraty poufności.
3. Błędy transmisji mogą prowadzić do nieprawidłowej autentykacji, np. przez uszkodzenie certyfikatów lub tokenów.
4. Błędy transmisji mogą być wykorzystywane w atakach, np. ataki typu bit-flipping na szyfrowane dane.
5. Protokoły bezpieczeństwa (np. TLS) mają wbudowane mechanizmy wykrywania i korygowania błędów, ale błędy transmisji mogą zwiększać obciążenie tych mechanizmów.

14 Współdzielenie kanału komunikacji
----

#### Opisz różne metody stosowane w protokołach współdzielenia kanału komunikacji.

1. Dostęp deterministyczny:
    - TDMA (Time Division Multiple Access): Czas jest podzielony na sloty, a każde urządzenie ma przydzielony określony slot czasowy.
    - FDMA (Frequency Division Multiple Access): Pasmo częstotliwości jest podzielone na kanały, a każde urządzenie ma przydzielony określony kanał.
    - CDMA (Code Division Multiple Access): Każde urządzenie używa unikalnego kodu do modulacji sygnału, co pozwala na równoczesną transmisję.
2. Dostęp losowy:
    - ALOHA: Urządzenia wysyłają dane w dowolnym momencie, a w przypadku kolizji retransmitują je po losowym czasie.
    - CSMA (Carrier Sense Multiple Access): Urządzenia nasłuchują kanału przed wysłaniem danych. Jeśli kanał jest zajęty, czekają.
    - CSMA/CA (Collision Avoidance): Używany w WiFi, dodaje mechanizmy unikania kolizji, takie jak RTS/CTS.
3. Dostęp kontrolowany:
    - Token Passing: Urządzenia przekazują sobie token, który uprawnia do transmisji.
    - Polling: Centralny kontroler pyta urządzenia, czy chcą transmitować.


#### Opisz metody współdzielenia kanału stosowane w:

1. ALOHA
    - Działanie:
        - Urządzenia wysyłają dane w dowolnym momencie.
        - Jeśli wystąpi kolizja (dwa urządzenia wysyłają jednocześnie), dane są retransmitowane po losowym czasie.
    - Warianty:
        - Czyste ALOHA: Brak synchronizacji czasowej.
        - Slotted ALOHA: Czas jest podzielony na sloty, a transmisja może rozpocząć się tylko na początku slotu.
2. Ethernet
    - Metoda: CSMA/CD (Carrier Sense Multiple Access with Collision Detection).
    - Działanie:
        - Urządzenia nasłuchują kanału przed wysłaniem danych.
        - Jeśli kanał jest wolny, rozpoczynają transmisję.
        - Jeśli wykryją kolizję (przez nasłuchiwanie sygnału), przerywają transmisję i retransmitują dane po losowym czasie (backoff algorithm).
3. WiFi
    - Metoda: CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance).
    - Działanie:
        - Urządzenia nasłuchują kanału przed wysłaniem danych.
        - Jeśli kanał jest wolny, wysyłają krótki sygnał RTS (Request to Send).
        - Odbiornik odpowiada sygnałem CTS (Clear to Send), co rezerwuje kanał.
        - Po otrzymaniu CTS, urządzenie rozpoczyna transmisję danych.
        - Jeśli kanał jest zajęty, urządzenie czeka losowy czas przed ponowną próbą.

#### Skomentuj efekt współdzielenia łącza przez równoczesne połączenia TCP.

1. Współzawodnictwo o przepustowość:
    - Wiele połączeń TCP współdzielących łącze konkuruje o dostępną przepustowość.
    - TCP używa mechanizmów kontroli przeciążeń (congestion control), które dostosowują szybkość transmisji do warunków sieciowych.
2. Fairness (sprawiedliwość):
    - Protokoły TCP starają się zapewnić sprawiedliwy podział przepustowości między połączenia.
    - Mechanizmy takie jak AIMD (Additive Increase Multiplicative Decrease) pomagają w równomiernym rozdziale zasobów.
3. Zjawisko "TCP Incast":
    - W środowiskach z wieloma równoczesnymi połączeniami TCP (np. w centrach danych), może wystąpić zjawisko "TCP Incast", gdzie wiele połączeń próbuje retransmitować dane jednocześnie, prowadząc do spadku wydajności.

#### Jak sieć BitTorrent dba o współdzielenie przepustowości dostępnej dla różnych partnerów?

1. Tit-for-Tat (wet za wet):
    - BitTorrent używa algorytmu Tit-for-Tat, który nagradza partnerów, którzy przesyłają dane, a karze tych, którzy tylko pobierają.
    - Jeśli użytkownik A przesyła dane do użytkownika B, użytkownik B będzie również przesyłał dane do użytkownika A.
2. Choking (blokowanie):
    - Każdy klient BitTorrent okresowo blokuje (choke) niektórych partnerów, aby dać szansę innym na przesyłanie danych.
    - Blokowanie jest oparte na szybkości przesyłania danych przez partnerów.
3. Optimistic Unchoking:
    - Klient BitTorrent okresowo odblokowuje (unchoke) losowego partnera, aby dać szansę nowym partnerom na przesyłanie danych.
    - Pomaga to w odkrywaniu nowych źródeł danych.
4. Rarest First:
    - Klient BitTorrent priorytetowo pobiera rzadkie fragmenty pliku, aby zwiększyć ich dostępność w sieci.
    - Pomaga to w równomiernym rozłożeniu obciążenia.
5. Endgame Mode:
    - Gdy klient pobiera ostatnie fragmenty pliku, wysyła żądania do wszystkich partnerów, aby przyspieszyć zakończenie pobierania.

15 Czas
----
#### NTP

NTP (Network Time Protocol) to protokół służący do synchronizacji czasu między urządzeniami w sieci. Jest szeroko stosowany w systemach rozproszonych, gdzie dokładny czas jest kluczowy (np. bankowość, logowanie zdarzeń).
1. Hierarchia serwerów czasu:
    - NTP używa hierarchicznej struktury serwerów czasu, zwanej stratum.
    - Stratum 0: Urządzenia referencyjne (np. zegary atomowe).
    - Stratum 1: Serwery bezpośrednio synchronizowane z urządzeniami Stratum 0.
    - Stratum 2: Serwery synchronizowane z Stratum 1, itd.
2. Wymiana pakietów:
    - Klient wysyła żądanie do serwera NTP, zawierające znacznik czasu (timestamp).
    - Serwer odpowiada, podając swój znacznik czasu.
    - Klient oblicza opóźnienie (delay) i różnicę czasu (offset) na podstawie czasu wysłania i odbioru pakietów.
3. Korekcja czasu:
    - Klient dostosowuje swój zegar na podstawie obliczonego offsetu.
    - NTP używa algorytmów filtracji i średniej ważonej, aby wybrać najbardziej dokładne źródło czasu.
4. Precyzja:
    - NTP może osiągnąć precyzję rzędu milisekund, a w optymalnych warunkach nawet mikrosekund.

#### Algorytmy wykrywania zagubionych pakietów i dobierania czasu oczekiwania, skąd wiadomo jaki timeout

1. Timeout:
    - Jeśli odpowiedź nie nadejdzie w określonym czasie, pakiet jest uznawany za zagubiony.
    - Czas oczekiwania (timeout) jest dynamicznie dostosowywany na podstawie opóźnienia sieci (RTT – Round-Trip Time).
2. Retransmisja:
    - W protokołach takich jak TCP, zagubione pakiety są retransmitowane po upływie timeoutu.
    - Dobieranie czasu oczekiwania:
3. Algorytm Karn/Partridge: Używany w TCP do estymacji czasu retransmisji (RTO – Retransmission Timeout).
    - RTO jest obliczany na podstawie średniego RTT i jego odchylenia standardowego.
    - Jeśli retransmisja jest konieczna, RTO jest podwajane (exponential backoff).

#### Przykłady wykorzystania czasu w protokołach bezpieczeństwa

1. TLS/SSL:
    - Certyfikaty zawierają daty ważności (notBefore, notAfter), które określają okres, w którym certyfikat jest ważny.
    - Protokół używa znaczników czasu do zapobiegania atakom typu replay.
2. Kerberos:
    - Używa znaczników czasu (timestamps) do uwierzytelniania i zapobiegania atakom replay.
    - Każdy bilet (ticket) zawiera znacznik czasu, który jest weryfikowany przez serwer.
3. OTP (One-Time Password):
    - Hasła jednorazowe są często generowane na podstawie czasu (TOTP – Time-Based One-Time Password).
    - Hasło jest ważne tylko przez krótki okres (np. 30 sekund).

#### Wykorzystanie czasu w technologiach sieciowych do łamania symetrii

1. Challenge-Response:
    - Serwer wysyła klientowi losowe wyzwanie (challenge) z znacznikiem czasu.
    - Klient odpowiada, używając wyzwania i znacznika czasu do obliczenia odpowiedzi.
    - Zapobiega to atakom replay, ponieważ każda odpowiedź jest unikalna.
2. Nonce:
    - Losowa wartość (nonce) jest generowana i wysyłana z znacznikiem czasu.
    - Nonce jest używany do zapewnienia świeżości komunikacji.

#### Jak szybko kończy się zapętlanie identyfikatorów?

Zapętlanie identyfikatorów (np. numerów sekwencji) może prowadzić do kolizji, jeśli identyfikatory są ponownie używane. Aby zapobiec temu problemowi:

- Wielkość przestrzeni identyfikatorów:
    - Im większa przestrzeń (np. 32-bitowe lub 64-bitowe identyfikatory), tym dłużej trwa zapętlanie.
- Czas zapętlania:
    - Dla 32-bitowych identyfikatorów przy szybkości 1 milion identyfikatorów na sekundę, zapętlanie nastąpi po około 1,2 godziny.
    - Dla 64-bitowych identyfikatorów, zapętlanie nastąpi po milionach lat.

#### Narzuty czasowe związane z protokołami TCP, HTTP i SSL

1. TCP:
    - Nawiązanie połączenia: 3-way handshake (1 RTT).
    - Retransmisja: W przypadku utraty pakietu, retransmisja zajmuje dodatkowy czas (zależny od RTO).
2. HTTP:
    - Połączenie TCP: 1 RTT (jeśli połączenie jest już nawiązane).
    - Żądanie i odpowiedź: 1 RTT.
3. SSL/TLS:
    - Nawiązanie połączenia: Pełne handshake zajmuje 2 RTT (dla TLS 1.3 – 1 RTT).
    - Resume session: 1 RTT (używając wcześniej uzgodnionych parametrów).

#### Sterowanie prędkością transmisji w protokołach opartych na UDP

Programista może sterować prędkością transmisji w protokołach UDP na kilka sposobów:

1. Określanie szybkości wysyłania:
    - Programista może ręcznie kontrolować szybkość wysyłania pakietów, np. przez wprowadzenie opóźnień między pakietami.
2. Mechanizmy kontroli przeciążeń:
    - Implementacja własnych mechanizmów kontroli przeciążeń, np. dostosowywanie szybkości wysyłania na podstawie informacji zwrotnej od odbiorcy.
3. Użycie protokołów nadrzędnych:
    - Protokoły takie jak QUIC (używany w HTTP/3) implementują kontrolę przeciążeń na poziomie aplikacji.
4. Bufferowanie:
    - Sterowanie rozmiarem bufora wysyłania, aby uniknąć przeciążenia sieci.

16 Mechanizmy bezpieczeństwa
------
#### Podstawowe wykorzystania
##### Funkcje Haszujące
Przykłady funkcji haszujących:
- MD5: 128-bitowy skrót (niezalecany ze względu na podatność na kolizje).
- SHA-1: 160-bitowy skrót (również niezalecany).
- SHA-256: 256-bitowy skrót (często używany w aplikacjach bezpieczeństwa).
- SHA-3: Najnowsza rodzina funkcji haszujących.

Przykłady zastosowań:

- Weryfikacja integralności danych: Skrót pliku jest obliczany przed i po przesłaniu, aby upewnić się, że dane nie zostały zmienione.
- Przechowywanie haseł: Hasła są przechowywane jako skróty, aby uniknąć przechowywania ich w postaci jawnej.
- Podpisy cyfrowe: Skrót wiadomości jest podpisywany kluczem prywatnym.

##### Kryptografia klucza symetrycznego

Kryptografia klucza symetrycznego używa tego samego klucza do szyfrowania i deszyfrowania danych. Klucz musi być bezpiecznie udostępniony obu stronom.

Przykłady algorytmów:
- AES (Advanced Encryption Standard): 128-, 192- lub 256-bitowy klucz.
- DES (Data Encryption Standard): 56-bitowy klucz (niezalecany ze względu na słabość).
- 3DES (Triple DES): Trzykrotne szyfrowanie DES (bardziej bezpieczne).

Przykłady zastosowań:
- Szyfrowanie plików: Pliki są szyfrowane kluczem symetrycznym przed przesłaniem.
- Komunikacja bezpieczna: Protokoły takie jak TLS używają kluczy symetrycznych do szyfrowania danych podczas transmisji.
- VPN: Klucze symetryczne są używane do szyfrowania ruchu między klientem a serwerem VPN.

##### Kryptografia klucza publicznego (asymetryczna)

Kryptografia klucza publicznego używa pary kluczy: publicznego (do szyfrowania) i prywatnego (do deszyfrowania). Klucz publiczny może być udostępniony publicznie, podczas gdy klucz prywatny musi pozostać tajny.

Przykłady algorytmów:

- RSA: Używany do szyfrowania i podpisów cyfrowych.
- ECC (Elliptic Curve Cryptography): Używany do szyfrowania i podpisów cyfrowych, oferuje lepszą wydajność niż RSA.
- ElGamal: Używany do szyfrowania i podpisów cyfrowych.

Przykłady zastosowań:

- Podpisy cyfrowe: Wiadomość jest podpisywana kluczem prywatnym, a weryfikowana kluczem publicznym.
- Wymiana kluczy: Klucze symetryczne są wymieniane za pomocą kryptografii klucza publicznego (np. w protokole TLS).
- Szyfrowanie danych: Dane są szyfrowane kluczem publicznym odbiorcy i deszyfrowane jego kluczem prywatnym.

#### Schematy negocjacji wspólnego sekretu
##### Diffie-Hellman

Działanie:
- **Publiczne** Obie strony uzgadniają liczbę pierwszą p i generator g
- **prywatne** Obie strony generują swój klucz prywatny a i b
- **klucz publiczny** Każda strona oblicza swój klucz publiczny
    - A = g^a mod p
    - B = g^b mod p
- **wspólny sekret** Obie strony obliczają wspólny sekret
    - strona A: s = B^a mod p
    - strona B: s = A^b mod p

Jest on używany do uzgodnienia klucza sesji w TLS

##### Needham-Schroeder
- Inicjacja:
    - Strona A wysyła do zaufanego serwera (TTP – Trusted Third Party) wiadomość zawierającą swoje dane i dane strony B.
- Generowanie klucza:
    - Serwer generuje klucz sesji K i wysyła go do strony A, zaszyfrowany kluczem publicznym strony B.
- Przekazanie klucza:
    - Strona A przekazuje klucz K stronie B, zaszyfrowany kluczem publicznym strony B.
- Uwierzytelnienie:
    - Strona B odszyfrowuje klucz K i wysyła do strony A wiadomość potwierdzającą, zaszyfrowaną kluczem K.

Uwierzytelnianie w systemach rozproszonych: Needham-Schroeder jest używany do bezpiecznej wymiany kluczy i uwierzytelniania w systemach takich jak Kerberos.

17 Bufory
-----

#### Problemy związane z brakiem buforowania
1. Utrata danych:
    - Jeśli dane nie są buforowane, a odbiorca nie jest gotowy do ich przetworzenia, mogą zostać utracone.
    - Przykład: W protokole UDP, brak buforowania może prowadzić do utraty pakietów.
2. Niska wydajność:
    - Brak buforowania może prowadzić do częstego blokowania się procesów, co zmniejsza przepustowość systemu.
    - Przykład: W aplikacjach strumieniowych, brak buforowania może powodować przerwy w odtwarzaniu.
3. Zwiększone opóźnienia:
    - Bez buforowania, dane muszą być przetwarzane na bieżąco, co może prowadzić do opóźnień w przypadku przeciążenia.

#### Problemy związane z za dużym buforowaniem

1. Bufferbloat:
    - Zbyt duże bufory mogą prowadzić do zwiększenia opóźnień (latencji) w sieci.
    - Przykład: W routerach, duże bufory mogą powodować, że pakiety czekają w kolejce zbyt długo, zwiększając opóźnienia.
2. Nadmierne zużycie pamięci:
    - Duże bufory zajmują dużo pamięci, co może prowadzić do wyczerpania zasobów systemowych.
    - Przykład: W serwerach, duże bufory mogą prowadzić do wyczerpania pamięci RAM.
3. Niesprawiedliwe wykorzystanie zasobów:
    - Duże bufory mogą prowadzić do sytuacji, w której niektóre połączenia monopolizują zasoby, podczas gdy inne są blokowane.
    - Przykład: W sieciach z dużymi buforami, połączenia TCP mogą wykorzystywać całą dostępną przepustowość, pozostawiając niewiele dla innych protokołów.

#### Wpływ buforowanie na protokoły
##### Ethernet i WIFI
- Ethernet:
    - Buforowanie w przełącznikach Ethernet pomaga zarządzać ruchem i unikać kolizji.
    - Zbyt małe bufory mogą prowadzić do utraty ramek, a zbyt duże – do zwiększenia opóźnień.
- WiFi:
    - Buforowanie w punktach dostępowych WiFi pomaga zarządzać ruchem w warunkach wysokiego obciążenia.
    - Zbyt małe bufory mogą prowadzić do utraty pakietów, a zbyt duże – do zwiększenia opóźnień i problemów z jakością usług (QoS).

##### IP
- Buforowanie w routerach:
    - Routery buforują pakiety IP, aby zarządzać ruchem i unikać przeciążeń.
    - Zbyt małe bufory mogą prowadzić do utraty pakietów, a zbyt duże – do zwiększenia opóźnień (bufferbloat).

##### TCP i UDP
- TCP:
    - TCP używa buforów do zarządzania przepływem danych i kontroli przeciążeń.
    - Zbyt małe bufory mogą prowadzić do spadku wydajności, a zbyt duże – do zwiększenia opóźnień i problemów z kontrolą przeciążeń.
- UDP:
    - UDP nie ma wbudowanych mechanizmów buforowania, więc aplikacje muszą same zarządzać buforami.
    - Zbyt małe bufory mogą prowadzić do utraty pakietów, a zbyt duże – do zwiększenia opóźnień i zużycia pamięci.

#### Strategia zarządzania buforem

1. Dynamiczne dostosowywanie rozmiaru bufora:
    - Rozmiar bufora jest dostosowywany dynamicznie w zależności od warunków sieciowych.
    - Przykład: Protokół TCP używa mechanizmów takich jak TCP Window Scaling do dynamicznego dostosowywania rozmiaru okna.
2. Active Queue Management (AQM):
    - Algorytmy AQM, takie jak RED (Random Early Detection), zarządzają kolejką pakietów, aby uniknąć przeciążenia i bufferbloat.
    - Przykład: RED losowo odrzuca pakiety, gdy kolejka zaczyna się zapełniać, co zachęca źródła do zmniejszenia szybkości transmisji.
3. Fair Queuing:
    - Algorytmy takie jak WFQ (Weighted Fair Queuing) dzielą przepustowość sprawiedliwie między różne strumienie danych.
    - Przykład: WFQ przypisuje wagę każdemu strumieniowi, aby zapewnić sprawiedliwy podział zasobów.
4. Priority Queuing:
    - Pakiety są priorytetyzowane na podstawie ich znaczenia (np. VoIP ma wyższy priorytet niż przeglądanie stron internetowych).
    - Przykład: DiffServ używa priorytetów do zarządzania ruchem w sieci.
5. Buffer Preallocation:
    - Bufory są wstępnie alokowane dla określonych aplikacji lub strumieni, aby zapewnić im gwarantowaną przepustowość.
    - Przykład: W sieciach QoS, bufory mogą być przydzielane dla aplikacji wrażliwych na opóźnienia, takich jak VoIP.

18 Adresowanie
-----


#### Opisz jak komputery są adresowane w protokołach:
##### Ethernet i WiFi,
- Adres MAC (Media Access Control):
    - Każda karta sieciowa ma unikalny 48-bitowy adres MAC, np. 00:1A:2B:3C:4D:5E.
    - Adres MAC jest używany do identyfikacji urządzeń w sieci lokalnej (LAN).
    - W Ethernet i WiFi komunikacja odbywa się na podstawie adresów MAC.
##### IP
- Adres IP:
    - Adres IP (IPv4 lub IPv6) identyfikuje urządzenie w sieci.
    - IPv4: 32-bitowy adres, np. 192.168.1.1.
    - IPv6: 128-bitowy adres, np. 2001:0db8:85a3::8a2e:0370:7334.
    - Adres IP jest używany do routowania pakietów między różnymi sieciami.
##### TCP i UDP
- Porty:
    - Porty identyfikują aplikacje lub usługi na urządzeniu.
    - TCP/UDP: Porty 16-bitowe, np. 80 (HTTP), 443 (HTTPS).
    - Adresowanie w TCP/UDP składa się z pary: adres IP + port, np. 192.168.1.1:80.
##### Chord
- Identyfikatory węzłów:
    - Węzły w Chord są identyfikowane przez identyfikatory haszowe (hash), zwykle 160-bitowe.
    - Identyfikator jest obliczany jako hash adresu IP lub nazwy węzła.
    - Przykład: Węzeł z adresem IP 192.168.1.1 może mieć identyfikator 0x3A7F....
##### DNS
- Nazwy domen:
    - Komputery są adresowane przez nazwy domenowe, np. www.example.com.
    - DNS tłumaczy nazwy domenowe na adresy IP.
    - Przykład: www.example.com → 93.184.216.34.
#### Opisz mechanizm maskarady adresów IP.
Maskarada adresów IP (NAT) to technika używana do mapowania wielu prywatnych adresów IP na jeden publiczny adres IP. Jest często stosowana w routerach domowych i firmowych.

Jak działa NAT?

1. Prywatne adresy IP:
    - Urządzenia w sieci lokalnej używają prywatnych adresów IP, np. 192.168.1.2.
    - Prywatne adresy nie są routowalne w Internecie.
2. Publiczny adres IP:
    - Router ma przypisany publiczny adres IP, np. 203.0.113.1.
3. Translacja:
    - Gdy urządzenie w sieci lokalnej wysyła pakiet do Internetu, router zamienia prywatny adres IP na publiczny.
    - Router przechowuje informacje o mapowaniu w tabeli NAT.
4. Odpowiedź:
    - Gdy odpowiedź wraca do routera, zamienia publiczny adres IP z powrotem na prywatny.
5. Przykład:
    - Urządzenie 192.168.1.2 wysyła pakiet do 93.184.216.34.
    - Router zamienia źródłowy adres IP na 203.0.113.1.
    - Odpowiedź wraca do 203.0.113.1, a router przekierowuje ją do 192.168.1.2.
#### Opisz działanie protokołów translacji adresów:
##### ARP
- Cel: Mapowanie adresów IP na adresy MAC w sieci lokalnej.
- Jak działa:
    - Urządzenie wysyła broadcast ARP z zapytaniem: "Kto ma adres IP 192.168.1.1?"
    - Urządzenie z tym adresem IP odpowiada: "Ja mam, mój adres MAC to 00:1A:2B:3C:4D:5E."
    - Nadawca zapisuje mapowanie w swojej tablicy ARP.
##### DHCP
- Cel: Automatyczne przypisywanie adresów IP urządzeniom w sieci.
- Jak działa:
    - Urządzenie wysyła broadcast DHCP Discover.
    - Serwer DHCP odpowiada ofertą (DHCP Offer) z dostępnym adresem IP.
    - Urządzenie akceptuje ofertę (DHCP Request).
    - Serwer potwierdza przypisanie adresu IP (DHCP Ack).
##### DNS
- Cel: Tłumaczenie nazw domenowych na adresy IP.
- Jak działa:
    - Urządzenie wysyła zapytanie DNS do serwera DNS: "Jaki jest adres IP dla www.example.com?"
    - Serwer DNS odpowiada: "Adres IP to 93.184.216.34."
    - Urządzenie zapisuje mapowanie w swojej pamięci podręcznej.

19 Pośredniczenie w komunikacji
-----
#### Skomentuj mechanizmy Proxy w protokole HTTP.
Proxy HTTP to serwer pośredniczący między klientem a serwerem docelowym. Pełni różne funkcje, takie jak buforowanie, filtrowanie, anonimizacja i poprawa wydajności.
Jak to działa ?

- Buforowanie:
    - Proxy przechowuje kopie często żądanych zasobów (np. strony WWW), aby zmniejszyć obciążenie serwera docelowego i przyspieszyć odpowiedzi dla klientów.
    - Przykład: Jeśli wielu użytkowników żąda tej samej strony, proxy może dostarczyć ją z bufora zamiast wysyłać żądanie do serwera.
- Filtrowanie:
    - Proxy może blokować niepożądane treści (np. reklamy, strony z malware) lub ograniczać dostęp do określonych zasobów.
    - Przykład: Firma może używać proxy do blokowania dostępu do mediów społecznościowych.
- Anonimizacja:
    - Proxy może ukrywać adres IP klienta, przekazując żądania do serwera docelowego jako własne.
    - Przykład: Użytkownik może używać proxy, aby ukryć swoją tożsamość podczas przeglądania Internetu.
- Kontrola dostępu:
    - Proxy może wymagać uwierzytelnienia użytkownika przed udzieleniem dostępu do zasobów.
    - Przykład: Proxy w firmie może wymagać logowania przed dostępem do Internetu.
#### Opisz zasadę działania mostów łączących technologię Ethernet i WiFi.
Most (bridge) to urządzenie, które łączy różne segmenty sieci (np. Ethernet i WiFi), umożliwiając komunikację między nimi.

Jak działa most Ethernet-WiFi?

- Przechwytywanie ramek:
    - Most przechwytuje ramki z jednego segmentu sieci (np. Ethernet) i przekazuje je do drugiego segmentu (np. WiFi).
- Filtrowanie:
    - Most analizuje adresy MAC w ramkach i decyduje, czy przekazać ramkę do drugiego segmentu.
    - Jeśli adres MAC docelowy znajduje się w tym samym segmencie, ramka nie jest przekazywana.
- Uczenie się adresów MAC:
    - Most uczy się adresów MAC urządzeń w obu segmentach, budując tablicę mapowań.
    - Dzięki temu wie, które urządzenia są w którym segmencie.
- Przekazywanie ramek:
    - Jeśli adres MAC docelowy znajduje się w innym segmencie, most przekazuje ramkę do tego segmentu.
- Przykład:
    - Urządzenie A (Ethernet) wysyła ramkę do urządzenia B (WiFi).
    - Most przechwytuje ramkę, sprawdza adres MAC B i przekazuje ramkę do segmentu WiFi.

#### Jak wykorzystać mechanizmy VPN do tunelowania i pośredniczenia w komunikacji?
VPN (Virtual Private Network) to technologia, która tworzy bezpieczne, zaszyfrowane połączenie między dwoma punktami w sieci.

Jak działa tunelowanie VPN?

- Tworzenie tunelu:
    - VPN tworzy zaszyfrowany tunel między klientem a serwerem VPN.
    - Wszystkie dane przechodzące przez tunel są szyfrowane.
- Pośredniczenie:
    - Serwer VPN działa jako pośrednik między klientem a Internetem.
    - Wszystkie żądania klienta są wysyłane przez serwer VPN, który przekazuje je dalej.
- Maskowanie adresu IP:
    - Adres IP klienta jest zastępowany adresem IP serwera VPN, co zapewnia anonimowość.
- Przykłady zastosowań:
    - Bezpieczny dostęp do sieci firmowej: Pracownicy mogą łączyć się z siecią firmową przez VPN z dowolnego miejsca.
    - Omijanie cenzury: Użytkownicy mogą używać VPN, aby uzyskać dostęp do zablokowanych stron.
    - Ochrona prywatności: VPN szyfruje ruch, chroniąc przed podsłuchem.
#### Jak wykorzystać protokół SOCKS Proxy do zbudowania prostej sieci cebulowej?
Jak zbudować prostą sieć cebulową za pomocą SOCKS Proxy?

- Łańcuch proxy:
    - Klient łączy się z serwerem SOCKS Proxy, który przekazuje ruch do kolejnego serwera SOCKS, tworząc łańcuch.
    - Każdy serwer w łańcuchu zna tylko poprzedni i następny serwer.
- Anonimizacja:
    - Każdy serwer w łańcuchu zastępuje adres IP klienta swoim adresem IP, co utrudnia śledzenie źródła ruchu.
- Szyfrowanie:
    - Każde połączenie między serwerami może być zaszyfrowane, aby zwiększyć bezpieczeństwo.
- Przykład:
    - Klient → Proxy 1 → Proxy 2 → Proxy 3 → Serwer docelowy.
    - Każdy proxy zna tylko poprzedni i następny krok w łańcuchu.

#### Jak realizowane są tunele IPSEC i IPv6 w IPv4?
##### Tunele IPSEC
Jak działa tunel IPSEC?

- Tworzenie tunelu:
    - IPSEC tworzy zaszyfrowany tunel między dwoma punktami końcowymi (np. routerami).
    - Wszystkie dane przechodzące przez tunel są szyfrowane.
- Tryby IPSEC:
    - Transport Mode: Szyfruje tylko ładunek pakietu IP.
    - Tunnel Mode: Szyfruje cały pakiet IP i opakowuje go w nowy pakiet IP.
- Użycie:
    - Tunele IPSEC są często używane do łączenia sieci firmowych przez Internet (VPN).
- Przykład:
    - Router A (siedziba firmy) → Tunel IPSEC → Router B (oddział firmy).

##### Tunele IPv6 w IPv4

Jak działa tunel IPv6 w IPv4?

- Enkapsulacja:
    - Pakiety IPv6 są opakowywane w pakiety IPv4.
    - Nagłówek IPv4 zawiera adresy źródłowy i docelowy tunelu.
- Przekazywanie:
    - Pakiety IPv6 są przesyłane przez sieć IPv4 jako zwykłe pakiety IPv4.
    - Na końcu tunelu pakiety są dekapsulowane i przekazywane jako IPv6.
- Użycie:
    - Tunele IPv6 w IPv4 są używane do stopniowego wdrażania IPv6 w sieciach, które nadal używają IPv4.
- Przykład:
    - Host A (IPv6) → Tunel IPv6 w IPv4 → Host B (IPv6).

## fin fin fin






