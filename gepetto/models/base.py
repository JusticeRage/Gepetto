import abc

class LanguageModel(abc.ABC):
    @abc.abstractmethod
    def query_model_async(self, query, cb):
        pass

def get_model(model, *args, **kwargs):
    """
    Instantiates a model based on its name
    :param model:
    :return:
    """
    if model == "gpt-3.5-turbo" or model == "gpt-4":
        from gepetto.models.openai import GPT
        return GPT(model)
    elif model == "codellama":       # yes, with CodeLLama (LLaMa-2) we can. See https://github.com/facebookresearch/codellama
        # and https://huggingface.co/TheBloke/CodeLlama-34B-Instruct-GGUF
        # and https://github.com/oobabooga/text-generation-webui
        # and https://github.com/oobabooga/text-generation-webui/tree/main/extensions/openai
        from gepetto.models.local_llm import CodeLLaMa
    return CodeLLaMa(model)
    else:
        raise ValueError(f"Fatal error: {model} does not exist!")
