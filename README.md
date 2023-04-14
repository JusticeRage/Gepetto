# Gepetto

Gepetto is a Python script which uses OpenAI's gpt-3.5-turbo model to provide meaning to functions decompiled by IDA Pro.
At the moment, it can ask gpt-3.5-turbo to explain what a function does, and to automatically rename its variables.
Here is a simple example of what results it can provide in mere seconds:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/comparison.png?raw=true)

## Setup

Simply drop this script (as well as the `gepetto-locales` folder) into your IDA plugins folder (`$IDAUSR/plugins`). 
By default, on Windows, this should be `%AppData%\Hex-Rays\IDA Pro\plugins` (you may need to create the folder).

You will need to add the required packages to IDA's Python installation for the script to work.
Find which interpreter IDA is using by checking the following registry key: 
`Computer\HKEY_CURRENT_USER\Software\Hex-Rays\IDA` (default on Windows: `%LOCALAPPDATA%\Programs\Python\Python39`).
Finally, with the corresponding interpreter, simply run: 

```
[/path/to/python] -m pip install -r requirements.txt
```

⚠️ You will also need to edit the script and add your own API key, which can be found on [this page](https://beta.openai.com/account/api-keys).
Please note that gpt-3.5-turbo queries are not free (although not very expensive) and you will need to set up a payment method.

⚠️ Warning ⚠️
Gepetto is now using OpenAI's latest gpt-3.5-turbo model. If you upgraded recently, make sure you're using a recent
version of the `openai` Python package. The `requirements.txt` file has been upgraded accordingly.

If you wish to use other model providers like ChatSonic (still GPT3.5 but different api provider) or BingGPT, make sure to add the necessary API keys.
For ChatSonic refer to https://docs.writesonic.com/reference/finding-your-api-key
For BingGPT we use https://rapidapi.com/stefano-pochet-stefano-pochet-default/api/chatgpt-4-bing-ai-chat-api .  You'll need to input your rapidapi key and get you bing_u_cookie.
The cookie tends to expire but BinGPT is pretty powerfull; it leverages GPT 4 and has internet connectivity.

⚠️ Warning ⚠️
The rename all sub_* functions will trigger A LOT of queries to openAI. The intent of that feature is to quickly name functions we haven't looked at yet and hopefully
help the analyst decide what functions are worth ignoring and which ones are worth focusing on.
This feature should be run as a last step before drilling down during the analysis process.
Ensure you use other methods at your disposal like lumina, idamagicstrings etc. to bulk rename sub_* functions before you run this. 
You may also want to run it with the models for which you have a free trial/subscription before using whichever model you pay a subscription for.

## Usage

Once the plugin is installed properly, you should be able to invoke it from the context menu of IDA's pseudocode window,
as shown in the screenshot below:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/usage.png?raw=true)

You can also use the following hotkeys:

- Ask gpt-3.5-turbo to explain the function: `Ctrl` + `Alt` + `H`
- Request better names for the function's variables: `Ctrl` + `Alt` + `R`

Initial testing shows that asking for better names works better if you ask for an explanation of the function first – I
assume because gpt-3.5-turbo then uses its own comment to make more accurate suggestions.
There is an element of randomness to the AI's replies. If for some reason the initial response you get doesn't suit you,
you can always run the command again.

## Limitations

- The plugin requires access to the HexRays decompiler to function.
- gpt-3.5-turbo is a general-purpose language model and may very well get things wrong! Always be critical of results returned!

## Translations

You can change Gepetto's language by editing the script's locale in the first lines. For instance, to use the plugin
in French, you would simply add:

```python
language = "fr_FR"
```
The chosen locale must match the folder names in the `gepetto-locales folder. If the desired language isn't available,
you can contribute to the project by adding it yourself! The translation portal to get involved is on 
[Transifex](https://www.transifex.com/gepetto/gepetto/).

## Acknowledgements

- [OpenAI](https://openai.com), for making this incredible chatbot, obviously
- [Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support
- [Kaspersky](https://kaspersky.com), for funding all my research
