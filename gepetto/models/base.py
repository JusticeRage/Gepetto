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
    if model == "gpt-3.5-turbo" or model == "gpt-4-1106-preview":
        from gepetto.models.openai import GPT
        return GPT(model)
    else:
        print(f"Warning:  {model} does not exist! Using default model (gpt-3.5-turbo).")
        from gepetto.models.openai import GPT
        return GPT("gpt-3.5-turbo")
