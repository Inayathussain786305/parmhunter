# parmhunter
Lightweight Bash tool for hunting URL parameters during bug bounty recon — great for discovering XSS, IDOR, SSRF, and LFI vectors.
# 🕵️‍♂️ ParmHunter – Parameter Discovery Tool for Bug Bounty Recon 🎯

**Parmhunter** is a lightweight, high-utility Bash tool developed by **Inayat Hussain** to find hidden or common parameters in target URLs during bug bounty reconnaissance. It helps uncover vulnerable query parameters for further testing, such as **XSS**, **SSRF**, **IDOR**, **LFI**, and more.

---

## 🌟 Features

- 🔍 Fuzz URLs for hidden or sensitive parameters
- 📤 Accepts list of URLs or single target
- 🎯 Designed for bug bounty recon workflows
- ⚡ Extremely fast and light — perfect for 4GB RAM laptops
- 📁 Generates clean output for manual review or automation
- ✅ No dependencies required

---

## 🛠️ How to Use

1. Make the script executable:
   ```bash
   chmod +x parmhunter.sh

    Run the tool:

./parmhunter.sh

Choose your input method:

    Paste a single URL (e.g., https://target.com)

    Provide a file with a list of URLs

ParmHunter will try common parameters like:

    ?id=123
    ?page=home
    ?redirect=https://evil.com
    ?next=dashboard
    ?file=../../etc/passwd

    Output will include parameterized URLs for manual or automated testing using tools like:

        ⚔️ XSSHunter

        🔧 FFUF

        🔥 Burp Suite

        🧪 Dalfox, KXSS, ParamSpider

📁 Example Output

https://target.com/page.php?id=1
https://target.com/page.php?redirect=target.com
https://target.com/file.php?file=../../etc/passwd

📌 Use Cases

    🛠️ Param discovery before fuzzing

    🔓 XSS, SSRF, IDOR parameter leads

    🔍 Recon stage of bug bounty methodology

    👨‍🎓 Learning parameter naming conventions

    🔐 Lateral movement in large apps

👤 Author

Made by:

Inayat Hussain (a.k.a. Inayat Raj Chohan)
🧠 Bug Bounty Hunter | Bash Dev | Cybersecurity Enthusiast
🌐 LinkedIn
📘 Facebook: Inayat Raj Chohan
🐙 GitHub: https://github.com/your-github-username
⚠️ Legal Disclaimer

Use ParmHunter only on systems you are authorized to test. Unauthorized scanning or probing is illegal. This tool is for ethical hackers, students, and red teamers working within the law.
🙌 Support My Work

If this tool helped you, please:

    🌟 Star the repository

    👨‍💻 Share it with your bug bounty friends

    💬 Give feedback and ideas

Together, let's make ethical hacking easier for learners and professionals around the world.
