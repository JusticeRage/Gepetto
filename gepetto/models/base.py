import abc


class LanguageModel(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def query_model_async(self, query, cb, additional_model_options) -> None:
        pass

    def __eq__(self, other):
        return self.get_menu_name() == other.get_menu_name()

    def __hash__(self):
        return self.get_menu_name().__hash__()

    @staticmethod
    @abc.abstractmethod
    def supported_models() -> list[str]:
        pass

    @staticmethod
    @abc.abstractmethod
    def get_menu_name() -> str:
        pass
