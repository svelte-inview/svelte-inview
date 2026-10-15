# Pozostałe PR-y po releasie 4.0.5

Release 4.0.5 to zmergowane #56, #57, #58 i #59. Tych czterech nie powtarzać. Poniższe PR-y idą dopiero potem, każdy jako osobny release albo osobny merge bez mieszania zmian zachowania w jednym diffie.

Wersje poniżej zakładają, że 4.0.5 już jest na npm.

## Kolejność

1. PR 5, cykl życia akcji.
2. PR 6, kierunek scrolla. Ten sam plik `src/inview.ts`, więc po PR 5.
3. PR 7, attachment. Też po PR 5, żeby zmiana opcji robiła czysty destroy i ponowny init.
4. PR 8, demo. Może iść równolegle z 5–7. Musi wejść przed PR 9.
5. PR 9, usunięcie starych eventów. Major. Na końcu.
6. PR 10, toolchain. Po 4.0.5, bez mieszania z 5–9. Przy przepisywaniu Rollupa `svelte` zostaje w `external`.

## PR 5. Cykl życia akcji

Pliki: `src/inview.ts`, test w `src/tests/inview.spec.ts`, ewentualnie nowa trasa w `test-app`.

- Akcja zwraca `update`. Zmiana `root`, `rootMargin`, `threshold` albo `unobserveOnEnter` rozłącza stary `IntersectionObserver` i zakłada nowy.
- `destroy` anuluje oczekujący `inview_init` z `tick()`. Odmontowanie albo szybka zmiana opcji nie wysyła `inview_init` na węzeł, który nie jest już obserwowany.

Svelte 5 woła `payload.update` tylko wtedy, gdy akcja go zwróci. Dziś zwracany jest sam `destroy`, więc opcje biorą się raz.

Wersja po merge: patch, następny po 4.0.5.

Sprawdzenie: strona, na której `rootMargin` zmienia się po pierwszym wejściu w viewport. Drugi próg ma użyć nowej wartości. Playwright na `/default-settings` zostaje zielony.

## PR 6. Kierunek scrolla

Pliki: `src/inview.ts`, test `direction` w `src/tests/inview.spec.ts`.

- Pierwszy callback nie zgłasza `down` / `right`. `scrollDirection.vertical` i `horizontal` zostają puste, dopóki nie ma poprzedniej pozycji.
- Każdy event dostaje własną kopię `scrollDirection`. Zapisanie `detail.scrollDirection` nie zmienia się przy kolejnym callbacku.

Istniejący test oczekuje początkowego `down`. Trzeba go przepisać.

To poprawka, ale ktoś mógł polegać na pierwszym `down`. W changelogu napisać to wprost. Wersja: patch albo minor, jeśli ta zmiana ma być widoczna osobno od PR 5.

## PR 7. Attachment

Pliki: nowy eksport obok `inview`, `src/index.ts`, typy, krótki fragment README.

- Zostaje `use:inview`.
- Dochodzi fabryka pod `{@attach}`, na przykład `inview(options)`, zgodna z `Attachment` ze `svelte/attachments`.
- Peer zostaje `svelte` `^3 || ^4 || ^5`. W README: attachment wymaga Svelte 5.29+.
- Opcje czytane przy tworzeniu attachmentu przebudowują observer, gdy są stanem. Dlatego PR 7 wchodzi po PR 5.

Wersja: minor.

Sprawdzenie: komponent Svelte 5 z `{@attach inview(options)}` i `oninview_enter`. Osobny scenariusz Playwright obok istniejącego `use:inview`.

## PR 8. Demo

Pliki: `demo/`.

- Svelte 5.
- Zejść z `on:enter` i `createEventDispatcher` w `demo/src/components/icon.svelte`.
- Zależność `svelte-inview` ma wskazywać lokalny build albo wersję z npm po 4.0.5, nie `^3.0.2`.

Nie jest potrzebne do działania paczki. Jest potrzebne przed PR 9, bo demo stoi na starej nazwie `enter`.

Osobny release nie jest konieczny. Wystarczy merge.

## PR 9. Usunięcie `change`, `enter`, `leave`, `init`

Pliki: `src/inview.ts`, typy eventów, README.

Akcja od v4 wysyła też stare nazwy. Po tym PR zostają tylko `inview_change`, `inview_enter`, `inview_leave`, `inview_init`.

Wersja: **5.0.0**. Nie łączyć z PR 5, 6 ani 7.

Warunek: README i demo nie słuchają już starych nazw.

## PR 10. Toolchain

Pliki: `package.json`, lockfile, `rollup.config.js`, ESLint, Husky, TypeScript.

- Rollup 4, TypeScript 5, ESLint pod Svelte 5.
- `svelte` zostaje w `external`. Bundle nadal zaczyna się od `import { tick } from 'svelte'`.
- Brak zmiany API. Osobny merge, bez wrzucania tego do PR 5–7.

Wersja użytkowa nie jest wymagana. Jak publish i tak idzie, wystarczy patch.
