import asyncio
import logging
import random
import array
import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import StatesGroup, State
from aiogram.types import Message, FSInputFile
from aiogram.filters import Command
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.client.default import DefaultBotProperties

# Логирование
logging.basicConfig(level=logging.INFO)

# Токены (реальные — не публикуй их в открытом доступе!)
BOT_TOKEN = "7697895116:AAGzzQYZt2AmJgaJnCUFgBbsG9QIVF6W904"
VT_API_KEY = "af8ae31b9e80e0bc5b3d1ccdc401ba4b02ea1bc34cc9aec245874d80864962c9"

# Инициализация бота
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())

# Функция генерации пароля
def pass_gen():
    MAX_LEN = 12
    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    LOCASE_CHARACTERS = list('abcdefghijkmnopqrstuvwxyz')
    UPCASE_CHARACTERS = list('ABCDEFGHJKLMNPQRSTUVWXYZ')
    SYMBOLS = list('@#$%=:?./|~>*()<')

    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS
    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    for _ in range(MAX_LEN - 4):
        temp_pass += random.choice(COMBINED_LIST)
    temp_pass_list = array.array('u', temp_pass)
    random.shuffle(temp_pass_list)
    return "".join(temp_pass_list)

# Состояния FSM
class LinkCheck(StatesGroup):
    waiting_for_url = State()

# Главное меню
main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="Методичка"), KeyboardButton(text="Проверить ссылку")],
        [KeyboardButton(text="Сгенерировать пароль")]
    ],
    resize_keyboard=True,
    input_field_placeholder="Выберите действие"
)

# Меню методички
method_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="Встроенные инструменты"), KeyboardButton(text="Microsoft Family Safety")],
        [KeyboardButton(text="Назад")]
    ],
    resize_keyboard=True,
    input_field_placeholder="Выберите раздел"
)

# Клавиатура назад при проверке ссылок
back_keyboard = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="Назад")]],
    resize_keyboard=True,
    input_field_placeholder="Отправьте ссылку или вернитесь назад"
)

# /start
@dp.message(Command("start"))
async def cmd_start(message: Message):
    await message.answer(
        "Привет! Выберите действие:",
        reply_markup=main_keyboard
    )

# Генерация пароля
@dp.message(F.text.lower() == "сгенерировать пароль")
async def send_generated_password(message: Message):
    password = pass_gen()
    await message.answer(f"🔐 Ваш сгенерированный пароль:\n<code>{password}</code>")

# Методичка
@dp.message(F.text.lower() == "методичка")
async def show_method_menu(message: Message):
    await message.answer(
        "Выберите интересующий раздел:",
        reply_markup=method_keyboard
    )

# Встроенные инструменты
@dp.message(F.text.lower() == "встроенные инструменты")
async def builtin_tools_info(message: Message):
    text = (
        "Отправляю методические материалы по настройке встроенных инструментов родительского контроля на устройства Android и Apple:\n"
        "Для устройств Android - https://clck.ru/3JSrNP\n"
        "Для устройств Apple - https://clck.ru/3JSrAV"
    )
    await message.answer(text)

# Microsoft Family Safety
@dp.message(F.text.lower() == "microsoft family safety")
async def microsoft_family_info(message: Message):
    text = (
        "Отправляю методические материалы по настройке родительского контроля через программное обеспечение Microsoft Family Safety:\n"
        "https://clck.ru/3JSrue"
    )
    await message.answer(text)

# Назад из методички
@dp.message(F.text.lower() == "назад")
async def go_back_to_main_menu(message: Message, state: FSMContext = None):
    if state:
        await state.clear()
    await message.answer(
        "Вы вернулись в главное меню.",
        reply_markup=main_keyboard
    )

# Команда "Проверить ссылку"
@dp.message(F.text.lower() == "проверить ссылку")
async def ask_for_url(message: Message, state: FSMContext):
    await state.set_state(LinkCheck.waiting_for_url)
    await message.answer(
        "Пожалуйста, отправьте ссылку, которую нужно проверить.",
        reply_markup=back_keyboard
    )

# Обработка ссылки
@dp.message(LinkCheck.waiting_for_url)
async def scan_and_report_url(message: Message, state: FSMContext):
    url = message.text.strip()
    if url.lower() == "назад":
        return await go_back_to_main_menu(message, state)
    if not url.startswith("http"):
        await message.answer("Пожалуйста, отправьте корректную ссылку, начинающуюся с http или https.")
        return
    await message.answer("Сканирую ссылку через VirusTotal...")
    try:
        async with aiohttp.ClientSession() as session:
            scan_api = 'https://www.virustotal.com/vtapi/v2/url/scan'
            scan_data = {'apikey': VT_API_KEY, 'url': url}
            async with session.post(scan_api, data=scan_data) as scan_response:
                if scan_response.status != 200:
                    await message.answer("Ошибка при отправке URL на сканирование.")
                    await state.clear()
                    return
                scan_result = await scan_response.json()
                scan_id = scan_result.get("scan_id")
                if not scan_id:
                    await message.answer("Не удалось получить scan_id от VirusTotal.")
                    await state.clear()
                    return
            report_api = 'https://www.virustotal.com/vtapi/v2/url/report'
            report_params = {'apikey': VT_API_KEY, 'resource': url, 'scan': 1}
            await asyncio.sleep(5)
            async with session.get(report_api, params=report_params) as report_response:
                if report_response.status != 200:
                    await message.answer("Ошибка при получении отчёта от VirusTotal.")
                    await state.clear()
                    return
                report = await report_response.json()
                if report.get("response_code") == 1:
                    positives = report.get("positives", 0)
                    total = report.get("total", 1)
                    detection_rate = positives / total * 100 if total else 0
                    permalink = report.get("permalink", "")
                    text = (
                        f"🔍 <b>Результаты анализа:</b>\n"
                        f"Обнаружено угроз: <b>{positives}</b>\n"
                        f"Всего проверок: <b>{total}</b>\n"
                        f"Процент заражения: <b>{detection_rate:.2f}%</b>\n\n"
                        f"<a href='{permalink}'>Смотреть полный отчёт на VirusTotal</a>"
                    )
                else:
                    text = (
                        f"❌ Не удалось найти данные по URL.\n"
                        f"{report.get('verbose_msg', '')}"
                    )
                await message.answer(text)
    except Exception:
        await message.answer("Произошла ошибка при работе с VirusTotal.")
    await state.clear()

# Запуск бота
async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
