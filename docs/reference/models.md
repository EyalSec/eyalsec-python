# Records

What the methods return. Every record is a frozen dataclass. Records built from a JSON object keep it in `raw`, so a field the server adds after this version of the library is still reachable; rows the API sends as arrays (events, machines) keep any values past the known ones in `extra`.

::: eyalsec._models
    options:
      show_root_heading: false
      members:
        - Event
        - EventPage
        - EventDetail
        - EventRun
        - Impact
        - Label
        - HiddenBy
        - Extension
        - Run
        - RunPage
        - EventStats
        - EventCount
        - SavedSearch
        - Machine
        - NewMachine
        - InstallCommand
        - Distro
        - PythonVersions
        - CIInstall
        - CIFindings
        - CIFinding
        - Filter
        - Rule
        - RuleTemplate
        - RuleTemplateList
        - TemplateItem
        - TemplateCategory
        - TemplateApplyResult
        - EventUniqueness
        - BlockedClient
        - ActivityEntry
        - ActivityPage
        - Account
        - APIKeyInfo
        - OnboardingState
        - parse_time
