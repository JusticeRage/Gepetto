import abc

GPT3_MODEL_NAME = "gpt-3.5-turbo-0125"
GPT4_MODEL_NAME = "gpt-4-turbo"
GPT4o_MODEL_NAME = "gpt-4o"
GROQ_MODEL_NAME = "llama3-70b-8192"
MISTRAL_MODEL_NAME = "mistralai/Mixtral-8x22B-Instruct-v0.1"


class LanguageModel(abc.ABC):
    @abc.abstractmethod
    def query_model_async(self, query, cb):
        pass


def get_model(model):
    """
    Instantiates a model based on its name
    :param model: The model to use
    :return:
    """
    if model == GPT3_MODEL_NAME or model == GPT4_MODEL_NAME or model == GPT4o_MODEL_NAME:
        from gepetto.models.openai import GPT
        return GPT(model)
    elif model == GROQ_MODEL_NAME:
        from gepetto.models.groq import Groq
        return Groq(model)
    elif model == MISTRAL_MODEL_NAME:
        from gepetto.models.together import Together
        return Together(model)
    else:
        print(f"Warning:  {model} does not exist! Using default model ({GPT4o_MODEL_NAME}).")
        from gepetto.models.openai import GPT
        return GPT(GPT4o_MODEL_NAME)
