import pandas as pd

# Mock Navy Blue Team format
navy_data = {
    "Target Address": ["10.0.0.1", "10.0.0.2"],
    "Observation": ["Default credentials used on router", "SMBv1 enabled on server"],
    "Severity": ["Critical", "High"],
    "Recommendation": ["Change password", "Disable SMBv1"]
}
df_navy = pd.DataFrame(navy_data)

# Mock NSA format
nsa_data = {
    "Host": ["wkstn-100", "wkstn-101"],
    "Vulnerability": ["Local admin password shared across endpoints", "Missing EDR agent"],
    "CVSS": [8.5, 7.2]
}
df_nsa = pd.DataFrame(nsa_data)

# Create an excel writer object
with pd.ExcelWriter('mock_multi_tab_report.xlsx') as writer:
    df_navy.to_excel(writer, sheet_name='Navy_Findings', index=False)
    df_nsa.to_excel(writer, sheet_name='NSA_Findings', index=False)

print("Created mock_multi_tab_report.xlsx")
