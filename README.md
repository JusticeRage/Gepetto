# Gepetto

Gepetto is a Python script which uses various large language models to provide meaning to functions 
decompiled by IDA Pro. At the moment, it can ask them to explain what a function does, and to automatically 
rename its variables. Here is a simple example of what results it can provide in mere seconds:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/comparison.png?raw=true)

## Setup

Simply drop this script (`gepetto.py`, as well as the `gepetto/` folder) into your IDA plugins folder (`$IDAUSR/plugins`). 
By default, on Windows, this should be `%AppData%\Hex-Rays\IDA Pro\plugins` (you may need to create it).

You will need to add the required packages to IDA's Python installation for the script to work.
Find which interpreter IDA is using by checking the following registry key: 
`Computer\HKEY_CURRENT_USER\Software\Hex-Rays\IDA` (default on Windows: `%LOCALAPPDATA%\Programs\Python\Python39`).
Finally, with the corresponding interpreter, simply run: 

```
[/path/to/python] -m pip install -r requirements.txt
```

⚠️ You will also need to edit the configuration file (found as `gepetto/config.ini`) and add your own API keys. For 
OpenAI, it can be found on [this page](https://beta.openai.com/account/api-keys).
Please note that API queries are usually not free (although not very expensive) and you will need to set up a payment 
method with the corresponding provider.

## Supported models

- [OpenAI](https://playground.openai.com/)
  - gpt-3.5-turbo-1106
  - gpt-4-turbo
  - gpt-4o (recommended for beginners)
- [Groq](https://console.groq.com/playground)
  -  llama3-70b-8192
- [Together](https://api.together.ai/)
  - mistralai/Mixtral-8x22B-Instruct-v0.1 (does not support renaming variables)

Adding support for additional models shouldn't be too difficult, provided whatever provider you're considering exposes
an API similar to OpenAI's. Look into the `gepetto/models` folder for inspiration, or open an issue if you can't figure
it out. Also make sure you edit `ida/ui.py` to add the relevant menu entries for your addition.

## Usage

Once the plugin is installed properly, you should be able to invoke it from the context menu of IDA's pseudocode window,
as shown in the screenshot below:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/usage.png?raw=true)

Switch between models supported by Gepetto from the Edit > Gepetto menu:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/select_model.png?raw=true)

You can also use the following hotkeys:

- Ask the model to explain the function: `Ctrl` + `Alt` + `H`
- Request better names for the function's variables: `Ctrl` + `Alt` + `R`

Initial testing shows that asking for better names works better if you ask for an explanation of the function first – I
assume because the model then uses its own comment to make more accurate suggestions.
There is an element of randomness to the AI's replies. If for some reason the initial response you get doesn't suit you,
you can always run the command again.

## Limitations

- The plugin requires access to the HexRays decompiler to function.
- All supported LLMs are general-purpose and may very well get things wrong! Always be 
  critical of results returned!

## Translations

You can change Gepetto's language by editing the locale in the configuration. For instance, to use the plugin
in French, you would simply add:

```ini
[Gepetto]
LANGUAGE = "fr_FR"
```

The chosen locale must match the folder names in `gepetto/locales`. If the desired language isn't available,
you can contribute to the project by adding it yourself! Create a new folder for the desired locale
(ex: `gepetto/locales/de_DE/LC_MESSAGES/`), and open a new pull request with the updated `.po` file, which you can
create by copying and editing `gepetto/locales/gepetto.pot` (replace all the lines starting with `msgstr` with the
localized version).  

## Acknowledgements

- [OpenAI](https://openai.com), for making these incredible models, obviously
- [Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support
- [Kaspersky](https://kaspersky.com), for initially funding this project
- [HarfangLab](https://harfanglab.io/), the current backer making this work possible
- [@vanhauser-thc](https://github.com/vanhauser-thc) for contributing ideas of additional models and providers to support via his [fork](https://github.com/vanhauser-thc/gepetto/)
- Everyone who contributed translations: @seifreed, @kot-igor, @ruzgarkanar, @orangetw
