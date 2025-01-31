This is a fork and an upgraded version of the original [Gepetto](https://github.com/JusticeRage/Gepetto) that added the (sider)[https://sider.ai] API support.  

# Description of the original Gepetto

Gepetto is a Python plugin which uses various large language models to provide meaning to functions 
decompiled by IDA Pro (≥ 7.4). It can leverage them to explain what a function does, and to automatically 
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

- [**Sider**](https:///sider.ai)  
  Basic models:  
  - sider (Sider Fusion)
  - gpt-4o-mini
  - claude-3-haiku
  - claude-3.5-haiku
  - gemini-1.5-flash
  - gemini-2.0-flash
  - llama-3
  - llama-3.3-70b
  - deepseek-chat (DeepSeek V3) 

  Advanced models:
  - gpt-4o
  - claude-3.5-sonnet
  - gemini-1.5-pro
  - llama-3.1-405b
  - o1-mini
  - o1
  - deepseek-reasoner (DeepSeek R1)
- [OpenAI](https://playground.openai.com/)
  - gpt-3.5-turbo-0125
  - gpt-4-turbo
  - gpt-4o (recommended for beginners)
- [Ollama](https://ollama.com/)
  - Any local model exposed through Ollama (will not appear if Ollama is not running)
- [Groq](https://console.groq.com/playground)
  - llama-3.1-70b-versatile
  - llama-3.2-90b-text-preview
  - mixtral-8x7b-32768
- [Together](https://api.together.ai/)
  - mistralai/Mixtral-8x22B-Instruct-v0.1 (does not support renaming variables)
- [Novita AI](https://novita.ai/)
  - deepseek/deepseek-r1
  - deepseek/deepseek-v3
  - meta-llama/llama-3.3-70b-instruct
  - meta-llama/llama-3.1-70b-instruct
  - meta-llama/llama-3.1-405b-instruct

Adding support for additional models shouldn't be too difficult, provided whatever provider you're considering exposes
an API similar to OpenAI's. Look into the `gepetto/models` folder for inspiration, or open an issue if you can't figure
it out.

## Usage

Once the plugin is installed properly, you should be able to invoke it from the context menu of IDA's pseudocode window,
as shown in the screenshot below:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/usage.png?raw=true)

Switch between models supported by Gepetto from the Edit > Gepetto menu:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/select_model.png?raw=true)

Gepetto also provides a CLI interface you can use to ask questions to the LLM directly from IDA. Make sure to select
`Gepetto` in the input bar:

![](https://github.com/JusticeRage/Gepetto/blob/main/readme/cli.png?raw=true)

### Hotkeys

The following hotkeys are available:

- Ask the model to explain the function: `Ctrl` + `Alt` + `G`
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

- [Sider](https://sider.ai) that provides alternative access to various models including gpt, claude, gemini, o1, deepseek, etc.
- [OpenAI](https://openai.com), for making these incredible models, obviously
- [Hex Rays](https://hex-rays.com/), the makers of IDA for their lightning fast support
- [Kaspersky](https://kaspersky.com), for initially funding this project
- [HarfangLab](https://harfanglab.io/), the current backer making this work possible
- [@vanhauser-thc](https://github.com/vanhauser-thc) for contributing ideas of additional models and providers to support via his [fork](https://github.com/vanhauser-thc/gepetto/)
- Everyone who contributed translations: @seifreed, @kot-igor, @ruzgarkanar, @orangetw

## Changes in this fork

#### the config.ini

This fork added the `API_PROVIDER` key that specifies the API provider Gepetto uses.  
For example, if `API_PROVIDER` is set to `sider`, none of API providers except `sider` will be used.  
```
[Gepetto]
MODEL = gpt-4o-mini

# Specify the program language. It can be "fr_FR", "zh_CN", or any folder in locales. Defaults to English.
LANGUAGE = 

# The name of the python module in `gepetto/models` folder, including sider, openai, etc.
API_PROVIDER = 
```
To implement this, the original `gepetto/models/model_manager.py` has been changed.  

Additionally, the `Sider` section is added:  
```
[Sider]

# Only TOKEN is required, other keys are optional
TOKEN = eyJhbGciOiJIUzI...
CONTEXT_ID =
COOKIE =
```
The token can be gained in your browser settings or developer tools if you've logged in [sider.ai](https://sider.ai). 
For Edge, you can view the cookie and token at [edge://settings/cookies/detail?site=sider.ai](edge://settings/cookies/detail?site=sider.ai). Do NOT include the `Bearer` header.  
The optional `CONTEXT_ID` is the conversation context ID, since the conversation is stored in the cloud rather than locally.   
The optional `COOKIE` is the additional cookie to be passed to sider.ai. If not provided, the `sider_ai_api` library will use a default cookie template.  
For more information about these keys, please refer to my own repository [sider-ai-api](https://github.com/qfcy/sider-ai-api).  

#### Additional changes

`gepetto/models/model_manager.py`: To implement the `API_PROVIDER` key in `config.ini`.  
`requirements.txt`: Added the line of `sider-ai-api`.  