import re
import requests
import pandas as pd
from bs4 import BeautifulSoup
from openpyxl import Workbook
import brotli

# Function to fetch the description from a vulnerability URL
def get_vulnerability_description(vuln_url, headers):
    if not vuln_url.startswith('http'):  # Check if the URL is valid
        return "Invalid vulnerability URL"
    
    response = requests.get(vuln_url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extracting the description from the provided HTML structure
        description_tag = soup.find("th", string="Description")
        if description_tag:
            # Find the next row (tr) to get the description text
            description_row = description_tag.find_parent("tr").find_next_sibling("tr")
            if description_row:
                description = description_row.get_text(strip=True)
                return description
        else:
            return "Description not found"
    else:
        return f"Failed to retrieve: {response.status_code}"

# Step 1: Extract module names and versions from the text file
def extract_modules_and_versions(text):
    version_pattern = r'(\w+Version)\s*=\s*"([\d.]+)"'
    library_pattern = r'(\w+)\s*=\s*\{\s*module\s*=\s*"([\w.-]+:[\w.-]+)",\s*version.ref\s*=\s*"(\w+Version)"\s*\}'

    version_matches = re.findall(version_pattern, text)
    versions = {match[0]: match[1] for match in version_matches}

    library_matches = re.findall(library_pattern, text)
    modules = []
    for match in library_matches:
        module_name = match[1]
        version_ref = match[2]
        module_version = versions.get(version_ref)
        modules.append((module_name, module_version))
    return modules

# Step 2: Scrape mvnrepository.com for release date, homepage, and vulnerabilities
def get_mvnrepository_info(module, version):
    group_id, artifact_id = module.split(':')
    base_url = f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}/{version}"
    print(f"base_url: {base_url}")  # Print base_url object for debugging

    # Headers to mimic a real browser request to avoid 403 errors
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",  # Accept Brotli, gzip, and deflate encoding
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive"
    }

    # Making the request
    response = requests.get(base_url, headers=headers)

    # Step 1: Handle compression if necessary
    response_content = response.content

    # Handle Brotli compression
    if response.headers.get('Content-Encoding') == 'br':
        try:
            response_content = brotli.decompress(response.content)
        except brotli.error as e:
            print(f"Brotli decompression failed: {e}")
            # Handle the error, maybe fallback to another approach or log it

    # Handle gzip compression
    elif response.headers.get('Content-Encoding') == 'gzip':
        response_content = response.content

    # Handle deflate compression
    elif response.headers.get('Content-Encoding') == 'deflate':
        response_content = response.content

    # Step 2: Detect encoding if not specified
    if response.encoding is None:
        detected_encoding = chardet.detect(response_content)['encoding']
        response_content = response_content.decode(detected_encoding, errors='replace')
    else:
        response_content = response_content.decode(response.encoding, errors='replace')

    # Check for 403 status code and print the base URL if encountered
    if response.status_code == 403:
        print(f"403 Forbidden - base_url: {base_url}")
        return "Unable to retrieve", "Unable to retrieve", "Unable to retrieve", "Unable to retrieve", "Unable to retrieve"

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract description
        description = "No description available"
        description_tag = soup.find("div", class_="im-description")
        if description_tag:
            description = description_tag.get_text(strip = True)

        # Extract Categories
        categories = "No Categories available"
        categories_tag = soup.find("th", string="Categories")
        if categories_tag:
            categories = categories_tag.find_next_sibling("td").find("a").get_text(strip = True) if categories_tag.find_next_sibling("td").find("a") else categories
            print(f"categories: {categories}")

        # Extract homepage URL based on <th>HomePage</th>
        homepage = "No homepage available"
        homepage_tag = soup.find("th", string="HomePage")
        if homepage_tag:
            homepage = homepage_tag.find_next_sibling("td").find("a")['href'] if homepage_tag.find_next_sibling("td").find("a") else homepage

        # Extract release date based on <th>Date</th>
        release_date = "Unknown"
        release_date_tag = soup.find("th", string="Date")
        if release_date_tag:
            release_date = release_date_tag.find_next_sibling("td").get_text(strip = True)
            print(f"release_date: {release_date}")


        # Extract vulnerabilities (Check for any known vulnerabilities)
        vulnerabilities = "No known vulnerabilities"
        vulnerabilities_tag = soup.find("th", string="Vulnerabilities")
        if vulnerabilities_tag:
            # Look for the <td> following the "Vulnerabilities" <th>
            vulnerabilities_td = vulnerabilities_tag.find_next_sibling("td")
            if vulnerabilities_td:
                # Find all <a> tags with class "vuln"
                vulnerability_list = vulnerabilities_td.find_all("a", class_="vuln")
                if vulnerability_list:
                    print(f"vulnerability_list: {vulnerability_list}")
                    vulnerabilities = []
                    for vuln in vulnerability_list:
                        vuln_url = vuln['href']
                        description = get_vulnerability_description(vuln_url, headers)  # Fetch vulnerability description
                        vulnerabilities.append(f"{vuln.get_text(strip=True)}: {description}")
                    vulnerabilities = ', '.join(vulnerabilities)

        return release_date, homepage, vulnerabilities, categories, description
    else:
        return "Unknown", "No homepage available", "No known vulnerabilities", "No Categories available", "No description available"

# Step 3: Generate XLSX file with extracted data
def generate_xlsx(modules_info, output_file="modules_info.xlsx"):
    # Create a pandas DataFrame
    df = pd.DataFrame(modules_info, columns=['Module', 'Version', 'Release Date', 'Description', 'vulnerabilities'])

    # Write the DataFrame to an Excel file
    df.to_excel(output_file, index=False)

    print(f"Data has been written to {output_file}")

# Main function to execute the workflow
def main():
    # Step 1: Read text from the file ML.txt
    with open('ML.txt', 'r') as file:
        text = file.read()

    # Step 2: Extract modules and versions
    modules = extract_modules_and_versions(text)

    # Separate test libraries to append later
    test_libraries = []

    # Step 3: Fetch information from mvnrepository.com and create list of module information
    modules_info = []
    for module, version in modules:
        release_date, homepage, vulnerabilities, categories, description = get_mvnrepository_info(module, version)

        # If category is "Testing Frameworks & Tools" or "Logging Frameworks", save it for appending later
        if categories in ["Testing Frameworks & Tools", "Logging Frameworks"]:
            print(f"Marking module {module} as test library.")
            test_libraries.append([module, version, release_date, description, vulnerabilities])
        else:
            modules_info.append([module, version, release_date, description, vulnerabilities])

    # Step 4: Append test libraries at the end of the list
    modules_info.extend(test_libraries)

    # Step 5: Generate XLSX file
    generate_xlsx(modules_info)

# Execute the main function
if __name__ == "__main__":
    main()