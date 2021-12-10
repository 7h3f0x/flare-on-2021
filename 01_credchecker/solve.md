# 01_credchecker

## Solution

```js
function checkCreds() {
    if (username.value == "Admin" && atob(password.value) == "goldenticket")
    {
        var key = atob(encoded_key);
        var flag = "";
        for (let i = 0; i < key.length; i++)
        {
            flag += String.fromCharCode(key.charCodeAt(i) ^ password.value.charCodeAt(i % password.value.length))
        }
        document.getElementById("banner").style.display = "none";
        document.getElementById("formdiv").style.display = "none";
        document.getElementById("message").style.display = "none";
        document.getElementById("final_flag").innerText = flag;
        document.getElementById("winner").style.display = "block";
    }
    else
    {
        document.getElementById("message").style.display = "block";
    }
}

```

Therefore enter username = "Admin"

and password to base64 encoding for "goldenticket"

```bash
echo -n goldenticket | base64
```

## Flag

> `enter_the_funhouse@flare-on.com`

