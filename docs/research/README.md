# Исследовательский каталог Applications

Дата наблюдения: 8 ноября 2026, Europe/Chisinau. Назначение — проектирование,
а не готовая база блокировки.

- [Инвентарь источников](application-source-inventory-2026-11-08.json): 490 protocol IDs
  nDPI 6.0 и 1555 именованных файлов V2Fly. Типы смешаны; это не число приложений.
- [Начальные mappings](application-catalog-seed.json): 15 семейств и 22 дочерних
  определения, всего 37 записей. Native IDs сверены с закреплённым заголовком;
  наличие ID не подтверждает распознавание конкретного приложения на пакетах.
- [Copyright / license notices](APPLICATION-CATALOG-NOTICES.md).
- [План реализации](../PLAN-APPLICATION-FILTERING.md).

Во всех начальных записях capabilities Block/Allow-over-port-DENY выключены.
Каталог не активирован, модель конфигурации и сервер не изменялись. Для production
нужны legal/engine gate, PCAP/kernel проверки, проверенные лицензии каждого feed,
подписанный OMR data bundle и явная активация через общий preview/apply.

В инвентаре сохранены exact commit/source URL, hash исходного заголовка и лицензий,
нативные engine IDs и blob SHA файлов провайдера. Имена провайдера остаются данными:
их нельзя исполнять как код, shell, BPF или regex.
