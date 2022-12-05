# Gepetto

Gepetto is a Python script which uses OpenAI's GPT-3 to provide meaning to functions decompiled by IDA Pro.
At the moment, it can ask GPT-3 to explain what a function does, and to automatically rename its variables.
Here is a simple example of what results it can provide in mere seconds:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/comparison.png?raw=true)

## Setup

Simply drop this script into your IDA plugins folder (`$IDAUSR/plugins`).

You will need to add the required packages to IDA's Python installation for the script to work.
Find which interpreter IDA is using by checking the following registry key: 
`Computer\HKEY_CURRENT_USER\Software\Hex-Rays\IDA` (default on Windows: `%LOCALAPPDATA%\Programs\Python\Python39`).
Finally, with the corresponding interpreter, simply run: 

```
[/path/to/python] -m pip install -r requirements.txt
```

⚠️ You will also need to edit the script and add your own API key, which can be found on [this page](https://beta.openai.com/account/api-keys).
Please note that GPT-3 queries are not free (although not very expensive) and you will need to setup a payment method.

## Usage

Once the plugin is installed properly, you should be able to invoke it from the context menu of IDA's pseudocode window,
as shown in the screenshot below:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/usage.png?raw=true)

You can also use the following hotkeys:

- Ask GPT-3 to explain the function: `Ctrl` + `Alt` + `H`
- Request better names for the function's variables: `Ctrl` + `Alt` + `R`

Initial testing shows that asking for better names works better if you ask for an explanation of the function first – I
assume because GPT-3 then uses its own comment to make more accurate suggestions.
There is an element of randomness to the AI's replies. If for some reason the initial response you get doesn't suit you,
you can always run the command again.

## Limitations

- The plugin requires access to the HexRays decompiler to function.
- GPT-3 is a general-purpose chatbot and may very well get things wrong! Always be critical of results returned!

## Acknowledgements

- [OpenAI](https://openai.com), for making this incredible chatbot, obviously
- [Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support
- [Kaspersky](https://kaspersky.com), for funding all my research
