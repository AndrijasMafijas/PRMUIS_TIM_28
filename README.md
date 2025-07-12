# PRMUIS_TIM_28

PRMUIS_TIM_28 je konzolna aplikacija za sigurnu komunikaciju između servera i više klijenata preko TCP i UDP protokola, uz podršku za dva kriptografska algoritma: **3DES** i **RSA**.

---

## Pregled

Ovaj projekat implementira:

- Mogućnost izbora komunikacionog protokola: TCP ili UDP  
- Dva algoritma šifrovanja poruka: simetrični 3DES i asimetrični RSA  
- Sigurnu razmenu ključeva i poruka uz integritet podataka  
- Istovremeni, neblokirajući rad servera sa više klijenata (multipleksiranje sa `Socket.Select`)  
- Praćenje i ispis performansi šifrovanja i dešifrovanja  

---

## Funkcionalnosti

### Server

- Pri pokretanju prima informacije o protokolu, algoritmu i portu preko UDP handshake paketa  
- Generiše i razmenjuje ključeve za izabrani algoritam  
- Čuva informacije o svakom klijentu u klasi `NacinKomunikacije`  
- Omogućava višekorisničku TCP i UDP komunikaciju sa multipleksiranjem  
- Prikazuje statistiku o broju poruka i količini obrađenih podataka za svaki algoritam  

### Klijent

- Korisniku omogućava izbor protokola (TCP/UDP) i algoritma (3DES/RSA)  
- Izračunava SHA heš izabranog algoritma i šalje ga serveru zajedno sa potrebnim informacijama  
- Šifruje i šalje poruke serveru  
- Prima i dešifruje poruke od servera  
- Podržava prekid komunikacije komandom `kraj`  

---

## Kako pokrenuti

1. Klonirajte repozitorijum:  
   ```bash
   git clone https://github.com/tvojusername/SecureComm.git

2. Izgradite projekat u Visual Studio ili iz komandne linije (prmuis -> server -> server.sln)

3. Pokrenite server:

    * Server čeka klijentski handshake na UDP portu 27015

    * Nakon handshake-a server otvara odgovarajući TCP ili UDP port za komunikaciju

4. Pokrenite klijenta:

    * Unesite IP adresu servera, port, protokol (TCP/UDP) i algoritam (3DES/RSA)

    * Počnite sa slanjem poruka

---

## Tehničke napomene

- **Multipleksiranje:** TCP server koristi `Socket.Select()` da bi neblokirajuće upravljao sa više klijenata istovremeno. Ova metoda omogućava da server prati spremnost utičnica za čitanje, čime se efikasno obrađuju višestruki klijenti bez blokiranja niti.
- **Klasa `NacinKomunikacije`:** Sadrži sve bitne informacije o klijentskoj konekciji i algoritmu šifrovanja, što omogućava lako upravljanje i identifikaciju veza.
- **Ključ za 3DES:** Simetrični ključ generiše klijent i bezbedno šalje serveru (preko RSA enkripcije ili direktno za UDP).
- **RSA enkripcija:** Server i klijent generišu parove ključeva; server šalje javni ključ klijentu, koji koristi za šifrovanje simetričnih ključeva ili direktnu komunikaciju.
- **Integritet podataka:** Poruke se prate heš vrednostima kreiranim SHA-256 algoritmom da bi se proverila ispravnost i sprečile izmene u toku prenosa.
- **Performanse:** Server prikazuje statistiku o količini obrađenih podataka (broj poruka, ukupno bajtova enkriptovanih i dekriptovanih) za svaki algoritam na kraju rada.
- **UDP handshake:** Komunikacija započinje UDP handshake paketom kojim se definišu protokol, algoritam i port, čime se inicira sigurna veza.

---

