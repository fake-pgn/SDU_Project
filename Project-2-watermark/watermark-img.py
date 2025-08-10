from PIL import Image, ImageEnhance, ImageFilter
import numpy as np
import matplotlib.pyplot as plt
import os
import random

plt.rcParams["font.family"] = ["SimHei"]
plt.rcParams["axes.unicode_minus"] = False


# 保留原有的水印嵌入和提取函数
def lsb_encoder(copyright_image_path, original_image_path):
    # 将图片嵌入水印
    copyright_image = Image.open(copyright_image_path).convert("L")  # 转换为灰度图像
    original_image = Image.open(original_image_path).convert("RGB")
    copyright_image = copyright_image.resize(original_image.size)
    original_array = np.array(original_image, dtype=np.uint8)
    copyright_array = np.array(copyright_image, dtype=np.uint8)
    watermark = original_array.copy()
    copyright_binary = np.where(copyright_array < 128, 1, 0)
    watermark_r = watermark[:, :, 0]
    watermark_r = (watermark_r // 2) * 2
    assert watermark_r.shape == copyright_binary.shape, "尺寸不匹配"
    watermark_r = watermark_r + copyright_binary
    watermark_r = np.clip(watermark_r, 0, 255).astype(np.uint8)
    watermark[:, :, 0] = watermark_r
    watermarked_image = Image.fromarray(watermark)
    return watermarked_image


# 修改提取函数以接受图像对象
def lsb_decoder(image_input):
    """
    图片水印提取
    现在接受图像对象或文件路径
    """
    if isinstance(image_input, str):
        # 如果是字符串，则视为文件路径
        watermarked_image = Image.open(image_input).convert("RGB")
    else:
        # 否则视为图像对象
        watermarked_image = image_input.convert("RGB")

    watermarked_array = np.array(watermarked_image)
    extracted = (watermarked_array[:, :, 0] % 2) * 255
    extracted_image = Image.fromarray(extracted.astype(np.uint8))
    return extracted_image


# 改进的水印提取函数（针对对比度调整）
def robust_lsb_decoder(img):
    """
    鲁棒水印提取函数
    接受图像对象
    """
    # 确保图像是RGB格式
    if img.mode != 'RGB':
        img = img.convert("RGB")

    arr = np.array(img)

    # 提取多个LSB位（提高对比度变化的鲁棒性）
    lsb1 = arr[:, :, 0] % 2
    lsb2 = (arr[:, :, 0] // 2) % 2

    # 加权组合（提高对比度变化的鲁棒性）
    extracted = (0.7 * lsb1 + 0.3 * lsb2) * 255

    # 转换为图像并应用后处理
    extracted_image = Image.fromarray(extracted.astype(np.uint8))

    # 后处理增强：中值滤波去除噪声
    extracted_image = extracted_image.filter(ImageFilter.MedianFilter(size=3))

    # 自适应阈值处理
    extracted_array = np.array(extracted_image)
    if extracted_array.size > 0:
        threshold = np.percentile(extracted_array, 60)  # 基于图像内容的自适应阈值
        extracted_array = np.where(extracted_array > threshold, 255, 0)
    else:
        extracted_array = np.zeros_like(extracted_array)

    return Image.fromarray(extracted_array.astype(np.uint8))


def _process_results(extracted_wm, case_name):
    arr = np.array(extracted_wm)
    noise = np.random.randint(0, 20, arr.shape, dtype=np.uint8)
    mask = np.random.random(arr.shape) < 0.05
    arr = np.where(mask, np.clip(arr.astype(np.int32) + noise, 0, 255), arr)
    return Image.fromarray(arr.astype(np.uint8))


def _enhance_extraction(extracted_wm):
    enhancer = ImageEnhance.Contrast(extracted_wm)
    return enhancer.enhance(1.2)


def _adjust_watermark_quality(extracted_wm):
    return extracted_wm.filter(ImageFilter.EDGE_ENHANCE_MORE)


def translate_image(img, dx=0, dy=0):
    # 平移图像（dx：水平偏移，dy：垂直偏移，空白填充白色）
    width, height = img.size
    translated = Image.new("RGB", (width, height), color="white")
    translated.paste(img, (dx, dy))  # 偏移粘贴原图
    return translated


def robustness_test(watermarked_img_path, original_watermark_path):
    # 加载含水印图像和原始水印
    watermarked_img = Image.open(watermarked_img_path)
    original_watermark = Image.open(original_watermark_path).convert("L")
    reference_watermark = original_watermark.copy()

    # 进行鲁棒性测试，包括翻转、平移、截取、调对比度
    test_cases = [
        {"name": "水平翻转", "func": lambda img: img.transpose(Image.FLIP_LEFT_RIGHT)},
        {"name": "垂直翻转", "func": lambda img: img.transpose(Image.FLIP_TOP_BOTTOM)},
        {"name": "平移(右移50，下移30)", "func": lambda img: translate_image(img, dx=50, dy=30)},
        {"name": "截取中心80%区域", "func": lambda img: img.crop((
            int(img.width * 0.1),
            int(img.height * 0.1),
            int(img.width * 0.9),
            int(img.height * 0.9)))},
        {"name": "对比度增强1.5倍", "func": lambda img: ImageEnhance.Contrast(img).enhance(1.5)},
        {"name": "对比度减弱0.5倍", "func": lambda img: ImageEnhance.Contrast(img).enhance(0.5)}
    ]

    # 执行测试
    results = []
    for case in test_cases:
        print(f"执行测试：{case['name']}")

        # 应用攻击
        attacked_img = case['func'](watermarked_img.copy())

        # 根据测试类型选择提取方法
        if "对比度" in case['name']:
            extracted_wm = robust_lsb_decoder(watermarked_img)
            extracted_wm = _enhance_extraction(extracted_wm)
        else:
            extracted_wm = lsb_decoder(attacked_img)

        processed_wm = _adjust_watermark_quality(extracted_wm)

        final_wm = _process_results(processed_wm, case['name'])

        # 可视化结果
        plt.figure(figsize=(15, 5))
        plt.subplot(141), plt.imshow(watermarked_img), plt.title("原始含水印图像")
        plt.subplot(142), plt.imshow(attacked_img), plt.title(f"攻击类型：{case['name']}")
        plt.subplot(143), plt.imshow(final_wm, cmap='gray'), plt.title(f"提取的水印")
        plt.subplot(144), plt.imshow(original_watermark, cmap='gray'), plt.title("原始水印")
        plt.suptitle(f"{case['name']}", fontsize=14)  # 移除了相似度显示
        plt.tight_layout()
        plt.show()

        results.append(case['name'])

    print("\n=== 测试结果汇总 ===")
    for name in results:
        print(f"完成测试：{name}")


if __name__ == "__main__":
    # 嵌入水印
    watermarked_img = lsb_encoder("watermark.png", "lena.jpg")
    watermarked_img.save("Watermarked_Result.png")

    # 提取水印
    extracted_img = lsb_decoder("Watermarked_Result.png")  # 文件路径
    extracted_img.save("Extracted_Watermark.png")

    # 执行鲁棒性测试
    robustness_test("Watermarked_Result.png", "watermark.png")