# Ayeene
## Reflected and DOM-based XSS vulnerability scanner

### This tool tests the following cases and warns you if there is a possibility that the input is vulnerable.

```
https://target.com/1.php?param1=value1<
https://target.com/1.php?param1=value1>
https://target.com/1.php?param1=value1”
https://target.com/1.php?param1=value1'
```
### reflection will be checked in source code, DOM and event handlers.


How to use:

```
git clone https://github.com/thepettypow/ayeene.git

pip install -r requirements.txt

python main.py https://target.com/1.php?param1=value1
```