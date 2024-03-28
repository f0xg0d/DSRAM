from dsram import likelihood, severity

#@title 365-day EPSS by CVE (leave blank if not CVE) { run: "auto" }

cve_ids = 'CVE-2021-44228' #@param {type:"string"}

if cve_ids:

  epss = likelihood.get_all_epss()

  # Regex is necessary to clean up messy data
  import re
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
    epss_30_day = epss.loc[cve]['epss_30_day']
    epss_30_day_list.append(epss_30_day)
    cve_age = nvd_data.loc[cve]['cve_age']
    cve_age_list.append(cve_age)
    epss_365_day = likelihood.epss_365_day_from_epss_30_day(cve_age, epss_30_day)
    epss_365_day_list.append(epss_365_day)

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
  print(df_epss[['epss_30_day', 'epss_365_day']])

else:
  cve_ids = False
