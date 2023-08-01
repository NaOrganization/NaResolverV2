#include <Windows.h>
#include "../NaResolver.h"

#define LOGGER_FUNCTION(level) ([](std::string m, ...)->void\
			{\
			m = #level " " + m + "\n";\
			va_list args;\
			va_start(args, m);\
			vprintf(m.c_str(), args);\
			va_end(args);\
			})

int WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		AllocConsole();
		freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
		NaResolver::Config config;
		config.enableLogger = true;
		config.logger.debug = LOGGER_FUNCTION([DEBUG]);
		config.logger.info = LOGGER_FUNCTION([INFO]);
		config.logger.error = LOGGER_FUNCTION([ERROR]);
		config.logger.fatal = LOGGER_FUNCTION([FATAL]);

		if (!MonoResolver->Setup(config))
			printf("Failed to setup I2Hrame!\n");
		MonoClass *klass = MonoResolver->GetClassEx("UnityEngine.CoreModule", "UnityEngine", "Camera");
		printf("Class: %p\n", klass);
		MonoMethodPointer method = MonoResolver->GetMethod(klass, "UnityEngine.Camera get_main()");
		printf("Method: %p\n", method);
		auto func = (void * (*)(MonoMethod*))method;
		void* camera = func(nullptr);
		printf("Camera: %p\n", camera);
		// if your camera was null, it means that the game is not loaded yet
		
		MonoResolver->Destroy();
		free(MonoResolver);

		FreeConsole();
	}
	return TRUE; // Successful DLL_PROCESS_ATTACH.
}
