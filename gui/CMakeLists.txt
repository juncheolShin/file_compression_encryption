    
qt_standard_project_setup()

qt_add_executable(hufcrypt_gui
    main.cpp
    MainWindow.cpp
    MainWindow.h
    MainWindow.ui
)

target_include_directories(hufcrypt_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(hufcrypt_gui PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Concurrent
    hufcrypt_core
)
