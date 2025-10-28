openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=RootCA"

Η εντολή openssl req καλεί το εργαλείο certificate request του openssl. Με την επιλογή -x509 του 
ζητάμε να δημιουργήσει ένα self-signed certificate, δηλαδή ένα πιστοποιητικό που υπογράφει τον 
εαυτό του και λειτουργεί ως Root CA. Το flag -nodes δηλώνει πως δεν θα κρυπτογραφηθεί το private 
key με password.Με την παράμετρο -days 365 καθορίζουμε ότι το πιστοποιητικό θα είναι έγκυρο για 
365 ημέρες. 
Το -newkey rsa:2048 σημαίνει ότι δημιουργείται ένα καινούργιο RSA keypair μήκους 2048 bit, το οποίο 
αποτελείται από ένα private key και ένα public key. Το private key αποθηκεύεται στο αρχείο ca.key, 
ενώ το public key ενσωματώνεται μέσα στο certificate ca.crt. 
Η παράμετρος -subj επιτρέπει να περάσουμε απευθείας το Distinguished Name (DN) του πιστοποιητικού 
χωρίς να μας ζητήσει διαδραστικά στοιχεία. Ορίζουμε τα πεδία: C=GR, ST=Crete, L=Chania, 
O=TechnicalUniversityofCrete, OU=ECELab  και CN=RootCA.
Μετά την εκτέλεση της εντολής δημιουργούνται δύο βασικά αρχεία, το ca.key, που είναι το 
private key του CA και το ca.crt, το public certificate του CA, το οποίο θα χρησιμοποιηθεί για 
να υπογράψει τα υπόλοιπα certificates.


Αφού δημιουργήσαμε το Root CA, το επόμενο βήμα ήταν να φτιάξουμε το πιστοποιητικό του server. 
Η διαδικασία γίνεται σε δύο στάδια: πρώτα δημιουργούμε ένα Certificate Signing Request μαζί με 
το private key του server και μετά το υπογράφουμε χρησιμοποιώντας το CA.

****Παράμετροι που έχουν εξηγηθεί προηγουμένως θα παραληφθούν.****

# 1. Create server key and CSR​
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=localhost"​


Η επιλογή -new δηλώνει ότι θέλουμε να δημιουργήσουμε ένα νέο CSR (Certificate Signing Request).
Μετά την εκτέλεση της εντολής δημιουργούνται δύο βασικά αρχεία, το server.key, που είναι το 
private key του server και το server.csr, το certificate signing request που θα σταλεί στο CA για 
υπογραφή.

Αφού έχουμε πλέον το server.csr, πρέπει να το υπογράψουμε με το CA που δημιουργήσαμε στο 
προηγούμενο βήμα.

# 2. Sign with CA​
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

Η εντολή openssl x509 χρησιμοποιείται για τη δημιουργία X.509 certificate. Με το flag -req 
δηλώνουμε ότι το input είναι ένα CSR που πρέπει να υπογραφεί. Η παράμετρος -CA ca.crt 
καθορίζει ποιο CA certificate θα χρησιμοποιηθεί ως issuer, ενώ το -CAkey ca.key δηλώνει το 
private key του CA, το οποίο είναι απαραίτητο για την υπογραφή.
Η επιλογή -CAcreateserial δημιουργεί ένα αρχείο σειριακού αριθμού (ca.srl), το οποίο 
χρησιμοποιείται από το openssl για να διασφαλίζει ότι κάθε νέο πιστοποιητικό έχει μοναδικό 
serial number.
Με την παράμετρο -out server.crt ορίζουμε το αρχείο εξόδου για το τελικό signed πιστοποιητικό. 
Τέλος, η επιλογή -sha256 δηλώνει ότι θέλουμε η υπογραφή του πιστοποιητικού να χρησιμοποιεί 
τον ασφαλή αλγόριθμο SHA-256.
Μετά την εκτέλεση αυτής της εντολής, δημιουργείται το αρχείο server.crt, το οποίο είναι 
πλέον ένα valid certificate signed από το CA.

# 1. Create client key and CSR​
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=client"

Μετά την εκτέλεση της εντολής δημιουργούνται δύο βασικά αρχεία, το client.key, που είναι το 
private key του client και το client.csr, το οποίο περιέχει το αίτημα υπογραφής που θα σταλεί 
στο CA.
​
# 2. Sign with CA​
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

Αφού δημιουργηθεί το client.csr, το επόμενο βήμα είναι να το υπογράψουμε με το ίδιο CA 
που εμπιστεύεται και ο server. Έτσι ο client θα αποκτήσει ένα πιστοποιητικό αναγνωρισμένο 
από το ίδιο root of trust.

Μετά την επιτυχή εκτέλεση της εντολής, έχουμε πλέον ένα πλήρες πιστοποιητικό client.crt 
που έχει υπογραφεί από το ca.crt.
Έτσι, ο client μπορεί να παρουσιάσει αυτό το πιστοποιητικό στον server κατά το TLS handshake, 
και ο server θα το αποδεχτεί, επειδή εμπιστεύεται την ίδια CA.

Χρησιμοποιήσαμε την πρώτη εντολή και στο string του subj αλλάξαμε τις πληροφορίες, με σκοπό 
να δημιουργήσαουμε ένα άλλο self signed certificate. Τρέξαμε τις εντολές για τον client, αλλά 
αυτή τη φορά χρησιμοποιήσαμε το νέο certificate για να δημιουργήσουμε το αρχείο rclient.crt.
Αυτό το κάναμε για να έχουμε έναν client που πρέπει να απορριφθεί.

Το πρόγραμμα εφαρμόζει ένα secure-client-server communication σύστημα, χρησιμοποιώντας την 
openssl βιβλιοθήκη και με mutual TLS επαλύθευση.
Το project αποτελείται από 3 προγράμματα:
Το server.c το οποίο είναι ένας TLS server ο οποίος χρειάζεται και κάνει validate client certificates,
τα οποία είναι signed από ένα trusted CA.
Το client.c το οποίο είναι ουσιαστικά ένα client το οποίο έχει ένα valid certificate, το οποίο είναι 
signed από την ίδια CA.
Το rclient.c το οποίο είναι ένα rogue client το οποίο χρησιμοποιεί ένα certificate το οποίο είναι 
issued από ένα untrusted CA, για να δείξουμε το handshake failure.

Κατά την διάρκεια του excecution, ο server και ο client κάνουν establish ένα TLS connection. Ο 
client στέλνει ένα απλό XML μήνυμα το οποίο περιέχει username/password, ο server κάνει validate 
τα credentials
και κάνει reply με ένα XML response.

1)
α.Το 8082 είναι το number στο οποίο ο server κάνει listen για εισερχόμενες συνδέσεις.
Κάθε υπηρεσία στο διαδίκτυο ή σε ένα λειτουργικό σύστημα συνδέεται με έναν αριθμό θύρας. 

Για παράδειγμα το HTTP χρησιμοποιεί τη θύρα 80 και το HTTPS χρησιμοποιεί τη 443,

Ο δικός μας server χρησιμοποιεί τη 8082 (ελεύθερος αριθμός που δεν είναι δεσμευμένος από άλλη 
υπηρεσία).
Έτσι, όταν γράφουμε ./server 8082, ενημερώνουμε το πρόγραμμα να ξεκινήσει να δέχεται συνδέσεις 
στο port 8082.

b. Can you run it on number 80, 443, 124? How can you achieve it?

Οι θύρες κάτω από το 1024 είναι privileged ports, δηλαδή μπορούν να χρησιμοποιηθούν μόνο 
από χρήστες με διαχειριστικά δικαιώματα (root).

Αν θέλουμε να το τρέξουμε εκεί, μπορείς να το κάνουμε με:

sudo ./server 80
sudo ./server 443

2)
a. What is 127.0.0.1?

Το 127.0.0.1 είναι η διεύθυνση IP του localhost, δηλαδή του ίδιου του υπολογιστή μας.

b. What is 8082?

Είναι ο ίδιος αριθμός θύρας στον οποίο κάνει listen ο server.
Ο client πρέπει να γνωρίζει σε ποια θύρα να συνδεθεί, ώστε να επικοινωνήσει με τον σωστό 
socket του server.
Αν ο server τρέχει σε διαφορετικό port, πρέπει να δηλωθεί το ίδιο και στην εντολή του client.


Όλες οι συναρτήσεις που εχουν προστεθεί και αφορούν το SSL είναι από το documentation του SSL 
(https://www.openssl.org/). Συγκεκριμένα υπάρχει η συνάρτηση verify_callback που καλείται ως 
όρισμα στην SSL_CTX_set_verify εντός του server.c ώστε να μπορει ο server να στείλει μήνυμα 
λάθους σε rogue clients που έχει απορρίψει. 
Μία παραδοχή που έχουμε κάνει είναι να αφαιρεθούν τα prompts από τον rclient για μη ζητάει 
είσοδο μόλις απορριφθεί αφού δεν έχει νόημα.

Konstantinos Kontos AM 2022030116
Christos Kadas AM 2022030076
