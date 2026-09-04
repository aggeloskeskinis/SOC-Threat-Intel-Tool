import requests
import time

# Το προσωπικό κλειδί - API KEY
API_KEY = "2256c1c0274cefef364f4a318b7d1bbbf950f390447fae9d6dfd92a004c19de5"

# Δείχνουμε την ταυτότητα μας για να μας αφήσουν να ρωτήσουμε
headers = {
    "accept" : "application/json", 
    "x-apikey" : API_KEY
}

# Ανοίγουμε ένα αρχείο report.txt για να καταγράφουμε τα αποτελέσματα
report_file = open("reports.txt", "w", encoding="utf-8")
report_file.write("=== THREAT INTELLIGENCE REPORT ===\n\n")

# Προσπαθώ να ανοίξω το αρχείο με τις ip
try:
    with open("targets.txt", "r", encoding="utf-8") as file:
        targets = file.readlines()
except FileNotFoundError:
    print("Δεν βρέθηκε το αρχείο targets.txt. Φτιάξτο στον ίδιο φάκελο")
    report_file.close()
    exit()

print(f"Βρέθηκαν {len(targets)} στόχοι στο αρχείο. Ξεκινάω τον έλεγχο... \n")

for target in targets:
    target = target.strip() #Καθαρίζουμε την ip από κενά ή αλλαγές γραμμής

    if not target:
        continue  #Αν η γραμμή είναι άδεια πήγαινε στην επόμενη

    target_length = len(target) 

    # Αν έχει γράμματα είναι Domain, αλλίως είναι IP
    if target_length == 32 or target_length == 64:
         endpoint = f"https://www.virustotal.com/api/v3/files/{target}"
         target_type = "File Hash"
    elif any(char.isalpha() for char in target) :
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        target_type = "Domain"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        target_type = "IP Address"
        


    print(f"Ελέγχω ({target_type}): {target}...\n")

    #Περιπτώσεις 
    try:
        response = requests.get(endpoint, headers=headers)

        #Ελέγχουμε τι μας απάντησε ο server του VirusTotal
        if (response.status_code == 200):

            # ΒΗΜΑ 1: Αντί για απλό κείμενο (text), λέμε στην Python να το διαβάσει ως JSON (Λεξικό)
            data = response.json()

            # ΒΗΜΑ 2: Ανοίγουμε τις "μπάμπουσκες" με τη σειρά (data -> attributes)
            attributes = data["data"]["attributes"]

            # ΒΗΜΑ 3: Τραβάμε τον Ιδιοκτήτη και τα Στατιστικά
            stats = attributes["last_analysis_stats"]

            if target_type == "IP Address":
                info = attributes.get("as_owner", "Άγνωστος Ιδιοκτήτης")
                info_label = "Ιδιοκτήτης"
            elif target_type == "Domain":
                info = attributes.get("registrar", "Άγνωστος Registrar")
                info_label = "Registrar"
            else:
                info = attributes.get("meaningful_name", "Άγνωστο Αρχείο")
                info_label = "Όνομα Αρχείου"



            # ΒΗΜΑ 4: Φτιάχνουμε το κείμενο της αναφοράς
            separator = "-" * 30

            result_block = (
                f" - [{target_type}]: {target}\n"
                f" - {info_label}: {info}\n"
                f" Καθαρή : {stats['harmless']} \n"
                f" Ύποπτη : {stats['suspicious']} \n"
                f" Κακόβουλη : {stats['malicious']} \n"
                f" {separator} \n\n"
            )

            print(result_block)
            report_file.write(result_block)
            

        else :
            err_msg = f" [{target_type}] {target} -> Σφάλμα:  (Κωδικός {response.status_code})"
            print(f" {err_msg}")
            report_file.write(err_msg)


    except Exception as e: 

       # Αυτό πιάνει σφάλματα όπως π.χ. να έχει κοπεί το ίντερνετ σου
       err_net = f" [{target_type}] {target} -> Πρόβλημα δικτύου: {e}\n"
       print(f" {err_net}")
       report_file.write(err_net)

       
    # Περιμένουμε 15 δευτερόλεπτα για να μην μας κόψει το API
    print("Περιμένω 15 δευτερόλεπτα...\n")
    time.sleep(15)

# Κλείνουμε το αρχείο reports.txt σωστά
report_file.write("\n===ΤΕΛΟΣ ΑΝΑΦΟΡΑΣ ===")
report_file.close()

print("Ο έλεγχος ολοκληρώθηκε! Δες τον φάκελο σου, έχει δημιουργηθεί το αρχείο reports.txt")