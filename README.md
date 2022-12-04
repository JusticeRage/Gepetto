Gepetto is a Python script which uses OpenAI's ChatGPT to provide meaning to functions decompiled by IDA Pro.

# Setup

Simply drop this script into your IDA plugins folder (`$IDAUSR/plugins`).

You will need to add the required packages to IDA's Python installation for the script to work.
Find which interpreter IDA is using by checking the following registry key: 
`Computer\HKEY_CURRENT_USER\Software\Hex-Rays\IDA` (default on Windows: `%LOCALAPPDATA%\Programs\Python\Python39`).
Finally, with the corresponding interpreter, simply run: 

```
[/path/to/python] -m pip install -r requirements.txt
```

⚠️ You will also need to edit the script and add your own API key, which can be found on [this page](https://beta.openai.com/account/api-keys).
Please note that ChatGPT queries are not free (although not very expensive) and you will need to setup a payment method.

# Usage

Once the plugin is installed properly, you should be able to invoke it from the context menu of IDA's pseudo code windows, as shown in the screenshot below:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/usage.png?raw=true)

# Limitations

- The plugin requires access to the HexRays decompiler to function.
- The request to ChatGPT is currently synchronous and will cause IDA to freeze during the query. I'm currently working on a workaround.
- ChatGPT is a general-purpose chatbot and may very well get things wrong! Always be critical of results returned!

# Acknowledgements

- [OpenAI](https://openai.com), for making this incredible chatbot, obviously
- [Kaspersky](https://kaspersky.com), for funding all my research
