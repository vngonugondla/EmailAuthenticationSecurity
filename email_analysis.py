import os
import csv
from email.parser import HeaderParser

def analyze_email(email_folder, filename):

    email = None
    
    with open(email_folder + filename, "r") as file:
        email = file.read()

    parser = HeaderParser()
    h = parser.parsestr(email)
    
    email_result = {
        "domain": h["From"],
        "filename": filename
    }
    authentication_results = h["Authentication-Results"]

    if ("dkim=" in authentication_results):
        dkim_split = authentication_results.split("dkim=")[1]
        email_result["dkim_result"] = dkim_split.split(" ")[0]
    else:
        email_result["dkim_result"] = "none"

    if ("spf=" in authentication_results):
        email_result["spf_result"] = authentication_results.split("spf=")[1].split(" ")[0]
    else:
        email_result["spf_result"] = "none"

    if ("dmarc=" in authentication_results):
        dmarc_split = authentication_results.split("dmarc=")[1]
        email_result["dmarc_result"] = dmarc_split.split(" ")[0]
        policy = dmarc_split.split("p=")[1].split(" ")[0]
        email_result["dmarc_policy"] = policy
    else:
        email_result["dmarc_result"] = "none"
    return email_result
    

        
def scan_folder(email_folder):
    results = []
    for filename in os.listdir(email_folder):
        if (filename.endswith(".eml")):
            email_result = analyze_email(email_folder, filename)
            results.append(email_result)
    return results
                    
def save_results(results, output_csv):
    header =  {
            "domain": "domain",
            "filename": "filename",
            "spf_result": "spf_result",
            "dmarc_result" :"dmarc_result",
            "dkim_result": "dkim_result",
            "dmarc_policy": "dmarc_policy"
    }
    
    results.insert(0, header)

    with open(output_csv, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["domain", "filename", "spf_result", "dkim_result", "dmarc_result", "dmarc_policy"])
        writer.writerows(results)
        

if __name__ == "__main__":
    folder = "emails/"
    output_csv = "email_auth_results.csv"

    results = scan_folder(folder)
    save_results(results, output_csv)

    print(f"Saved results to {output_csv}")