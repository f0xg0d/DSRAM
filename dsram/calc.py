from dsram import likelihood, severity
import pandas as pd
import argparse
import re
parser = argparse.ArgumentParser()

parser.add_argument("-i", "--input", type=str, dest="input_file",
                    action="store", required=True)

args = parser.parse_args()


df = pd.ExcelFile(args.input_file).parse('Nessus result') #could convert to not hardcoded input?

x=[]
x.append(df['CVE'])
cve_list = df['CVE'].tolist()
cve_list = map(str, cve_list)
cve_list_clean=[]
cve_filter = re.compile(r'CVE-200[2-9]|CVE-20[1-9][0-9]')
for cve in cve_list:
  if re.match(cve_filter, cve):
    cve_list_clean.append(cve)
cve_list_clean = list(dict.fromkeys(cve_list_clean))
cve_ids = ' '.join(str(cve) for cve in cve_list_clean)
print('This might take a while...')
if cve_ids:

  epss = likelihood.get_all_epss()

  # CVE regular expression (from https://stackoverflow.com/questions/60178826/extracting-cve-info-with-a-python-3-regular-expression)
  cve_pattern = r'CVE-\d{4}-\d{1,10}'
  cve_pattern_years = r'CVE-\d{4}'

  #get years of cves to scope nvd data pull
  cve_years = re.findall(cve_pattern_years, cve_ids)
  cve_years_list = []

  for year in cve_years:
    new_year = year.split('CVE-')[1]
    if new_year not in cve_years_list:
      cve_years_list.append(new_year)

  nvd_data = likelihood.get_nvd_data(cve_years_list)

  #search for CVE references using RegEx
  cves = re.findall(cve_pattern, cve_ids)

  epss_30_day_list = []
  cve_age_list = []
  epss_365_day_list = []

  for cve in cves:
    try:
      epss_30_day = epss.loc[cve]['epss_30_day']
      epss_30_day_list.append(epss_30_day)
      cve_age = nvd_data.loc[cve]['cve_age']
      cve_age_list.append(cve_age)
      epss_365_day = likelihood.epss_365_day_from_epss_30_day(cve_age, epss_30_day)
      epss_365_day_list.append(epss_365_day)
    except:
      epss_30_day_list.append('-')
      cve_age_list.append('-')
      epss_365_day_list.append('-')
      pass

  import pandas as pd

  pd.options.display.float_format = '{:.2%}'.format
  df_epss = pd.DataFrame(
      {'cve_id': cves,
      'epss_30_day': epss_30_day_list,
      'epss_365_day': epss_365_day_list,
      'cve_age': cve_age_list
      })

  df_epss = df_epss.set_index('cve_id')
  print('Risk of Occurence - by vulnerability')
  print(df_epss[['epss_30_day', 'epss_365_day']].to_string())

else:
  cve_ids = False
